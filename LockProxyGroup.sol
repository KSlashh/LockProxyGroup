// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.6.0;
pragma experimental ABIEncoderV2;

library Utils {

    /* @notice      Convert the bytes array to bytes32 type, the bytes array length must be 32
    *  @param _bs   Source bytes array
    *  @return      bytes32
    */
    function bytesToBytes32(bytes memory _bs) internal pure returns (bytes32 value) {
        require(_bs.length == 32, "bytes length is not 32.");
        assembly {
            // load 32 bytes from memory starting from position _bs + 0x20 since the first 0x20 bytes stores _bs length
            value := mload(add(_bs, 0x20))
        }
    }

    /* @notice      Convert bytes to uint256
    *  @param _b    Source bytes should have length of 32
    *  @return      uint256
    */
    function bytesToUint256(bytes memory _bs) internal pure returns (uint256 value) {
        require(_bs.length == 32, "bytes length is not 32.");
        assembly {
            // load 32 bytes from memory starting from position _bs + 32
            value := mload(add(_bs, 0x20))
        }
        require(value <= 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, "Value exceeds the range");
    }

    /* @notice      Convert uint256 to bytes
    *  @param _b    uint256 that needs to be converted
    *  @return      bytes
    */
    function uint256ToBytes(uint256 _value) internal pure returns (bytes memory bs) {
        require(_value <= 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, "Value exceeds the range");
        assembly {
            // Get a location of some free memory and store it in result as
            // Solidity does for memory variables.
            bs := mload(0x40)
            // Put 0x20 at the first word, the length of bytes for uint256 value
            mstore(bs, 0x20)
            //In the next word, put value in bytes format to the next 32 bytes
            mstore(add(bs, 0x20), _value)
            // Update the free-memory pointer by padding our last write location to 32 bytes
            mstore(0x40, add(bs, 0x40))
        }
    }

    /* @notice      Convert bytes to address
    *  @param _bs   Source bytes: bytes length must be 20
    *  @return      Converted address from source bytes
    */
    function bytesToAddress(bytes memory _bs) internal pure returns (address addr)
    {
        require(_bs.length == 20, "bytes length does not match address");
        assembly {
            // for _bs, first word store _bs.length, second word store _bs.value
            // load 32 bytes from mem[_bs+20], convert it into Uint160, meaning we take last 20 bytes as addr (address).
            addr := mload(add(_bs, 0x14))
        }

    }
    
    /* @notice      Convert address to bytes
    *  @param _addr Address need to be converted
    *  @return      Converted bytes from address
    */
    function addressToBytes(address _addr) internal pure returns (bytes memory bs){
        assembly {
            // Get a location of some free memory and store it in result as
            // Solidity does for memory variables.
            bs := mload(0x40)
            // Put 20 (address byte length) at the first word, the length of bytes for uint256 value
            mstore(bs, 0x14)
            // logical shift left _a by 12 bytes, change _a from right-aligned to left-aligned
            mstore(add(bs, 0x20), shl(96, _addr))
            // Update the free-memory pointer by padding our last write location to 32 bytes
            mstore(0x40, add(bs, 0x40))
       }
    }

    /* @notice          Do hash leaf as the multi-chain does
    *  @param _data     Data in bytes format
    *  @return          Hashed value in bytes32 format
    */
    function hashLeaf(bytes memory _data) internal pure returns (bytes32 result)  {
        result = sha256(abi.encodePacked(byte(0x0), _data));
    }

    /* @notice          Do hash children as the multi-chain does
    *  @param _l        Left node
    *  @param _r        Right node
    *  @return          Hashed value in bytes32 format
    */
    function hashChildren(bytes32 _l, bytes32  _r) internal pure returns (bytes32 result)  {
        result = sha256(abi.encodePacked(bytes1(0x01), _l, _r));
    }

    /* @notice              Compare if two bytes are equal, which are in storage and memory, seperately
                            Refer from https://github.com/summa-tx/bitcoin-spv/blob/master/solidity/contracts/BytesLib.sol#L368
    *  @param _preBytes     The bytes stored in storage
    *  @param _postBytes    The bytes stored in memory
    *  @return              Bool type indicating if they are equal
    */
    function equalStorage(bytes storage _preBytes, bytes memory _postBytes) internal view returns (bool) {
        bool success = true;

        assembly {
            // we know _preBytes_offset is 0
            let fslot := sload(_preBytes_slot)
            // Arrays of 31 bytes or less have an even value in their slot,
            // while longer arrays have an odd value. The actual length is
            // the slot divided by two for odd values, and the lowest order
            // byte divided by two for even values.
            // If the slot is even, bitwise and the slot with 255 and divide by
            // two to get the length. If the slot is odd, bitwise and the slot
            // with -1 and divide by two.
            let slength := div(and(fslot, sub(mul(0x100, iszero(and(fslot, 1))), 1)), 2)
            let mlength := mload(_postBytes)

            // if lengths don't match the arrays are not equal
            switch eq(slength, mlength)
            case 1 {
                // fslot can contain both the length and contents of the array
                // if slength < 32 bytes so let's prepare for that
                // v. http://solidity.readthedocs.io/en/latest/miscellaneous.html#layout-of-state-variables-in-storage
                // slength != 0
                if iszero(iszero(slength)) {
                    switch lt(slength, 32)
                    case 1 {
                        // blank the last byte which is the length
                        fslot := mul(div(fslot, 0x100), 0x100)

                        if iszero(eq(fslot, mload(add(_postBytes, 0x20)))) {
                            // unsuccess:
                            success := 0
                        }
                    }
                    default {
                        // cb is a circuit breaker in the for loop since there's
                        //  no said feature for inline assembly loops
                        // cb = 1 - don't breaker
                        // cb = 0 - break
                        let cb := 1

                        // get the keccak hash to get the contents of the array
                        mstore(0x0, _preBytes_slot)
                        let sc := keccak256(0x0, 0x20)

                        let mc := add(_postBytes, 0x20)
                        let end := add(mc, mlength)

                        // the next line is the loop condition:
                        // while(uint(mc < end) + cb == 2)
                        for {} eq(add(lt(mc, end), cb), 2) {
                            sc := add(sc, 1)
                            mc := add(mc, 0x20)
                        } {
                            if iszero(eq(sload(sc), mload(mc))) {
                                // unsuccess:
                                success := 0
                                cb := 0
                            }
                        }
                    }
                }
            }
            default {
                // unsuccess:
                success := 0
            }
        }

        return success;
    }

    /* @notice              Slice the _bytes from _start index till the result has length of _length
                            Refer from https://github.com/summa-tx/bitcoin-spv/blob/master/solidity/contracts/BytesLib.sol#L246
    *  @param _bytes        The original bytes needs to be sliced
    *  @param _start        The index of _bytes for the start of sliced bytes
    *  @param _length       The index of _bytes for the end of sliced bytes
    *  @return              The sliced bytes
    */
    function slice(
        bytes memory _bytes,
        uint _start,
        uint _length
    )
        internal
        pure
        returns (bytes memory)
    {
        require(_bytes.length >= (_start + _length));

        bytes memory tempBytes;

        assembly {
            switch iszero(_length)
            case 0 {
                // Get a location of some free memory and store it in tempBytes as
                // Solidity does for memory variables.
                tempBytes := mload(0x40)

                // The first word of the slice result is potentially a partial
                // word read from the original array. To read it, we calculate
                // the length of that partial word and start copying that many
                // bytes into the array. The first word we copy will start with
                // data we don't care about, but the last `lengthmod` bytes will
                // land at the beginning of the contents of the new array. When
                // we're done copying, we overwrite the full first word with
                // the actual length of the slice.
                // lengthmod <= _length % 32
                let lengthmod := and(_length, 31)

                // The multiplication in the next line is necessary
                // because when slicing multiples of 32 bytes (lengthmod == 0)
                // the following copy loop was copying the origin's length
                // and then ending prematurely not copying everything it should.
                let mc := add(add(tempBytes, lengthmod), mul(0x20, iszero(lengthmod)))
                let end := add(mc, _length)

                for {
                    // The multiplication in the next line has the same exact purpose
                    // as the one above.
                    let cc := add(add(add(_bytes, lengthmod), mul(0x20, iszero(lengthmod))), _start)
                } lt(mc, end) {
                    mc := add(mc, 0x20)
                    cc := add(cc, 0x20)
                } {
                    mstore(mc, mload(cc))
                }

                mstore(tempBytes, _length)

                //update free-memory pointer
                //allocating the array padded to 32 bytes like the compiler does now
                mstore(0x40, and(add(mc, 31), not(31)))
            }
            //if we want a zero-length slice let's just return a zero-length array
            default {
                tempBytes := mload(0x40)

                mstore(0x40, add(tempBytes, 0x20))
            }
        }

        return tempBytes;
    }
    function isContract(address account) internal view returns (bool) {
        // This method relies in extcodesize, which returns 0 for contracts in
        // construction, since the code is only stored at the end of the
        // constructor execution.

        // According to EIP-1052, 0x0 is the value returned for not-yet created accounts
        // and 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 is returned
        // for accounts without code, i.e. `keccak256('')`
        bytes32 codehash;
        bytes32 accountHash = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;
        // solhint-disable-next-line no-inline-assembly
        assembly { codehash := extcodehash(account) }
        return (codehash != 0x0 && codehash != accountHash);
    }
}

library SafeMath {
    /**
     * @dev Returns the addition of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `+` operator.
     *
     * Requirements:
     * - Addition cannot overflow.
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");

        return c;
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return sub(a, b, "SafeMath: subtraction overflow");
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     * - Subtraction cannot overflow.
     *
     * _Available since v2.4.0._
     */
    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b <= a, errorMessage);
        uint256 c = a - b;

        return c;
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `*` operator.
     *
     * Requirements:
     * - Multiplication cannot overflow.
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");

        return c;
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        return div(a, b, "SafeMath: division by zero");
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts with custom message on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     *
     * _Available since v2.4.0._
     */
    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        // Solidity only automatically asserts when dividing by 0
        require(b != 0, errorMessage);
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold

        return c;
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * Reverts when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        return mod(a, b, "SafeMath: modulo by zero");
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * Reverts with custom message when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     *
     * _Available since v2.4.0._
     */
    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b != 0, errorMessage);
        return a % b;
    }
}

library SafeERC20 {
    using SafeMath for uint256;

    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }

    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        // solhint-disable-next-line max-line-length
        require((value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
    }

    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 newAllowance = token.allowance(address(this), spender).add(value);
        callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }

    function safeDecreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 newAllowance = token.allowance(address(this), spender).sub(value);
        callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     */
    function callOptionalReturn(IERC20 token, bytes memory data) private {
        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
        // we're implementing it ourselves.

        // A Solidity high level call has three parts:
        //  1. The target address is checked to verify it contains contract code
        //  2. The call itself is made, and success asserted
        //  3. The return value is decoded, which in turn checks the size of the returned data.
        // solhint-disable-next-line max-line-length
        require(Utils.isContract(address(token)), "SafeERC20: call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = address(token).call(data);
        require(success, "SafeERC20: low-level call failed");

        if (returndata.length > 0) { // Return data is optional
            // solhint-disable-next-line max-line-length
            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
        }
    }
}

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

interface IEthCrossChainManager {
    function crossChain(uint64 _toChainId, bytes calldata _toContract, bytes calldata _method, bytes calldata _txData) external returns (bool);
}

abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
        return msg.data;
    }
}

abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor () internal {
        address msgSender = _msgSender();
        _owner = msgSender;
        emit OwnershipTransferred(address(0), msgSender);
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(isOwner(), "Ownable: caller is not the owner");
        _;
    }

    /**
     * @dev Returns true if the caller is the current owner.
     */
    function isOwner() public view returns (bool) {
        return _msgSender() == _owner;
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions anymore. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby removing any functionality that is only available to the owner.
     */
    function renounceOwnership() public onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public  onlyOwner {
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     */
    function _transferOwnership(address newOwner) internal {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

contract ERC20Pro is Context, IERC20 {
    mapping (address => uint256) private _balances;

    mapping (address => mapping (address => uint256)) private _allowances;

    uint256 private _totalSupply;

    string private _name;
    string private _symbol;
    uint8 private _decimals;
    address public minter;

    constructor (string memory name_, string memory symbol_, uint8 decimals_) public {
        _name = name_;
        _symbol = symbol_;
        _decimals = decimals_;
        minter = _msgSender();
    }

    function name() public view virtual returns (string memory) {
        return _name;
    }

    function symbol() public view virtual returns (string memory) {
        return _symbol;
    }

    function decimals() public view virtual returns (uint8) {
        return _decimals;
    }
    
    function mint(address to, uint256 amount) public virtual {
        require(minter == _msgSender(), "!minter");
        _mint(to, amount);
    }
    
    function burn(uint256 amount) public virtual {
        _burn(_msgSender(), amount);
    }
    
    function burnFrom(address account, uint256 amount) public virtual {
        uint256 currentAllowance = allowance(account, _msgSender());
        require(currentAllowance >= amount, "ERC20: burn amount exceeds allowance");
        _approve(account, _msgSender(), currentAllowance - amount);
        _burn(account, amount);
    }
    
    function totalSupply() public view virtual override returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) public view virtual override returns (uint256) {
        return _balances[account];
    }

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    function allowance(address owner, address spender) public view virtual override returns (uint256) {
        return _allowances[owner][spender];
    }

    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        _approve(_msgSender(), spender, amount);
        return true;
    }

    function transferFrom(address sender, address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(sender, recipient, amount);

        uint256 currentAllowance = _allowances[sender][_msgSender()];
        require(currentAllowance >= amount, "ERC20: transfer amount exceeds allowance");
        _approve(sender, _msgSender(), currentAllowance - amount);

        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public virtual returns (bool) {
        _approve(_msgSender(), spender, _allowances[_msgSender()][spender] + addedValue);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual returns (bool) {
        uint256 currentAllowance = _allowances[_msgSender()][spender];
        require(currentAllowance >= subtractedValue, "ERC20: decreased allowance below zero");
        _approve(_msgSender(), spender, currentAllowance - subtractedValue);

        return true;
    }

    function _transfer(address sender, address recipient, uint256 amount) internal virtual {
        require(sender != address(0), "ERC20: transfer from the zero address");
        require(recipient != address(0), "ERC20: transfer to the zero address");

        _beforeTokenTransfer(sender, recipient, amount);

        uint256 senderBalance = _balances[sender];
        require(senderBalance >= amount, "ERC20: transfer amount exceeds balance");
        _balances[sender] = senderBalance - amount;
        _balances[recipient] += amount;

        emit Transfer(sender, recipient, amount);
    }

    function _mint(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: mint to the zero address");

        _beforeTokenTransfer(address(0), account, amount);

        _totalSupply += amount;
        _balances[account] += amount;
        emit Transfer(address(0), account, amount);
    }

    function _burn(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: burn from the zero address");

        _beforeTokenTransfer(account, address(0), amount);

        uint256 accountBalance = _balances[account];
        require(accountBalance >= amount, "ERC20: burn amount exceeds balance");
        _balances[account] = accountBalance - amount;
        _totalSupply -= amount;

        emit Transfer(account, address(0), amount);
    }

    function _approve(address owner, address spender, uint256 amount) internal virtual {
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual { }
}

contract Hub {
    
    event CrossChainEvent(uint64 from_Id, uint64 to_Id, address fromContract, address toContract, bytes method, bytes txData);
    
    mapping(address => uint64) public ContractIdMap;
    
    function bind(uint64 chainID, address contractAddr) public {
        ContractIdMap[contractAddr] = chainID;
    }
    
    function crossChain(uint64 _toChainId, bytes memory _toContract, bytes memory _method, bytes memory _txData) public returns (bool) {
        address toContract = Utils.bytesToAddress(_toContract);
        uint64 _fromChainId = ContractIdMap[msg.sender];
        require(_fromChainId != 0, "!fromContract");
        require(ContractIdMap[toContract] == _toChainId, "!toContract" );
        
        bytes memory returnData;
        bool success;
        
        (success, returnData) = toContract.call(abi.encodePacked(bytes4(keccak256(abi.encodePacked(_method, "(bytes,bytes,uint64)"))), abi.encode(_txData, Utils.addressToBytes(msg.sender), _fromChainId)));
    
        require(success == true, "EthCrossChain call business contract failed");
        
        emit CrossChainEvent(_fromChainId, _toChainId, msg.sender, toContract, _method, _txData);
        
        return true;
    }
    
}

contract LockProxyGroup is Ownable {
    using SafeMath for uint;
    using SafeERC20 for IERC20;
    
    uint64 chainId;
    address managerContract;
    mapping(uint64 => bytes) public proxyHashMap;
    mapping(bytes20 => uint8) public groupTokenNumMap;
    mapping(bytes20 => bytes) public groupOwnerMap;
    mapping(bytes20 => uint64) public groupCreateChainIdMap;
    mapping(address => mapping(bytes20 => uint)) public groupBalance;
    mapping(bytes20 => mapping(uint64 => bytes)) public groupTokenHashMap;
    mapping(bytes20 => mapping(uint => uint64)) public indexedGroupTokenChainId;
    
    event RegisterGroupEvent(bytes owner, uint64 ownerChainId, bytes20 groupKey, uint8 groupTokenNum);
    event UpdateGroupEvent(bytes20 oldKey, bytes20 newKey);
    event AddCrossChainLiquidityEvent(address donator, bytes20 groupKey, address asset, uint amount);
    event UnlockEvent(bytes20 GroupKey, address toAssetHash, address toAddress, uint256 amount);
    event LockEvent(bytes20 GroupKey, address fromAssetHash, address fromAddress, uint64 toChainId, bytes toAssetHash, bytes toAddress, uint256 amount);
    
    constructor(uint64 _chainId, address _ccm) public {
        chainId = _chainId;
        managerContract = _ccm;
    }
    
    modifier onlyManagerContract() {
        require(_msgSender() == managerContract, "msgSender is not EthCrossChainManagerContract");
        _;
    }
    
    function setManagerContract(address ethCCMAddr) onlyOwner public {
        managerContract = ethCCMAddr;
    }
    
    function bindProxyHash(uint64 toChainId, bytes memory toProxyHash) onlyOwner public {
        proxyHashMap[toChainId] = toProxyHash;
    }
    
    function ownerCreateGroup(uint8 num, uint64[] memory tokenChainIds, bytes[] memory tokenAddrs) public returns(bytes20 key) {
        key = generateKey(chainId, Utils.addressToBytes(msg.sender), num, tokenChainIds, tokenAddrs);
        require(groupTokenNumMap[key]==0, "group already registered");
        
        bytes memory groupData = abi.encode(chainId, Utils.addressToBytes(_msgSender()), num, tokenChainIds, tokenAddrs, key);
        for (uint i=0; i<num; i++) {
            require(tokenChainIds[i] > (i==0 ? 0 : tokenChainIds[i-1]) , "not asc chainIds!");
            groupTokenHashMap[key][tokenChainIds[i]] = tokenAddrs[i];
            indexedGroupTokenChainId[key][i] = tokenChainIds[i];
            if (chainId != tokenChainIds[i]) { 
                IEthCrossChainManager(managerContract).crossChain(tokenChainIds[i], proxyHashMap[tokenChainIds[i]], "registerGroup", groupData);
            }
        }
        
        groupOwnerMap[key] = Utils.addressToBytes(_msgSender());
        groupCreateChainIdMap[key] = chainId;
        groupTokenNumMap[key] = num;
        
        RegisterGroupEvent(Utils.addressToBytes(_msgSender()), chainId, key, num);
    }
    
    function registerGroup(bytes memory groupData, bytes memory fromContract, uint64 fromChainId) public onlyManagerContract returns(bool) {
        bytes memory groupOwner;
        uint64 ownerChainId;
        uint8 groupTokenNum;
        uint64[] memory tokenChainIds;
        bytes[] memory tokenAddrs;
        bytes20 groupKey;
        (ownerChainId, groupOwner, groupTokenNum, tokenChainIds, tokenAddrs, groupKey) = abi.decode(groupData, (uint64, bytes, uint8, uint64[], bytes[], bytes20));
        // bytes20 key = generateKey(ownerChainId, groupOwner, groupTokenNum, tokenChainIds, tokenAddrs);
        // require(key==groupKey, "unmatch group key");
        require(groupTokenNumMap[groupKey]==0, "group already registered");
        
        for (uint i=0; i<groupTokenNum; i++) {
            groupTokenHashMap[groupKey][tokenChainIds[i]] = tokenAddrs[i];
            indexedGroupTokenChainId[groupKey][i] = tokenChainIds[i];
        }
        
        groupOwnerMap[groupKey] = groupOwner;
        groupCreateChainIdMap[groupKey] = ownerChainId;
        groupTokenNumMap[groupKey] = groupTokenNum;
        
        RegisterGroupEvent(groupOwner, ownerChainId, groupKey, groupTokenNum);
        
        return true;
    }
    
    function ownerUpdateGroup(bytes20 oldKey, uint8 groupTokenNum, uint64[] memory tokenChainIds, bytes[] memory tokenAddrs) public {
        require(groupTokenNumMap[oldKey]!=0, "group do not exisit");
        require(Utils.equalStorage(groupOwnerMap[oldKey], Utils.addressToBytes(_msgSender())), "not group owner");
        require(groupCreateChainIdMap[oldKey] == chainId, "group not create on this chain");
        
        bytes20 newKey = generateKey(chainId, Utils.addressToBytes(_msgSender()), groupTokenNum, tokenChainIds, tokenAddrs);
        bytes memory updateData = abi.encode(chainId, Utils.addressToBytes(_msgSender()), groupTokenNum, tokenChainIds, tokenAddrs, oldKey, newKey);
        bytes memory groupData = abi.encode(chainId, Utils.addressToBytes(_msgSender()), groupTokenNum, tokenChainIds, tokenAddrs, newKey);
        
        uint index = 0;
        uint64 idTmp = indexedGroupTokenChainId[oldKey][index];
        uint8 oldNum = groupTokenNumMap[oldKey];
        for (uint i=0; i<groupTokenNum; i++) {
            if (tokenChainIds[i] == chainId) { 
                address thisToken = Utils.bytesToAddress(tokenAddrs[i]);
                groupBalance[thisToken][newKey] ==  groupBalance[thisToken][oldKey]; 
                delete groupBalance[thisToken][oldKey];
            }
            if (tokenChainIds[i] == idTmp) {
                require(Utils.equalStorage(groupTokenHashMap[oldKey][idTmp], tokenAddrs[i]), "unmatch token list");
                idTmp = index==oldNum ? 0 : indexedGroupTokenChainId[oldKey][++index];
                if (chainId != tokenChainIds[i]) { 
                    IEthCrossChainManager(managerContract).crossChain(tokenChainIds[i], proxyHashMap[tokenChainIds[i]], "updateGroup", updateData);
                }
            } else {
                if (chainId != tokenChainIds[i]) { 
                    IEthCrossChainManager(managerContract).crossChain(tokenChainIds[i], proxyHashMap[tokenChainIds[i]], "registerGroup", groupData);
                }
            }
            groupTokenHashMap[newKey][tokenChainIds[i]] = tokenAddrs[i];
            indexedGroupTokenChainId[newKey][i] = tokenChainIds[i];
        }
        require(index==oldNum, "unmatch token list");
        
        groupOwnerMap[newKey] = Utils.addressToBytes(msg.sender);
        groupCreateChainIdMap[newKey] = chainId;
        groupTokenNumMap[newKey] = groupTokenNum;
        _deleteGroup(oldKey);
        
        UpdateGroupEvent(oldKey, newKey);
    }
    
    function updateGroup(bytes memory updateData, bytes memory fromContract, uint64 fromChainId) public onlyManagerContract returns(bool) {
        bytes memory groupOwner;
        uint64 ownerChainId;
        uint8 groupTokenNum;
        uint64[] memory tokenChainIds;
        bytes[] memory tokenAddrs;
        bytes20 oldKey;
        bytes20 newKey;
        (ownerChainId, groupOwner, groupTokenNum, tokenChainIds, tokenAddrs, oldKey, newKey) = abi.decode(updateData, (uint64, bytes, uint8, uint64[], bytes[], bytes20, bytes20));

        for (uint i=0; i<groupTokenNum; i++) {
            if (tokenChainIds[i] == chainId) { 
                address thisToken = Utils.bytesToAddress(tokenAddrs[i]);
                groupBalance[thisToken][newKey] ==  groupBalance[thisToken][oldKey];
                delete groupBalance[thisToken][oldKey];
            }
            groupTokenHashMap[newKey][tokenChainIds[i]] = tokenAddrs[i];
            indexedGroupTokenChainId[newKey][i] = tokenChainIds[i];
        }
        
        groupOwnerMap[newKey] = groupOwner;
        groupCreateChainIdMap[newKey] = ownerChainId;
        groupTokenNumMap[newKey] = groupTokenNum;
        _deleteGroup(oldKey);
        
        UpdateGroupEvent(oldKey, newKey);
        
        return true;
    }
    
    function addCrossChainLiquidity(bytes20 groupKey, address asset, uint amount) public {
        require(groupTokenNumMap[groupKey]!=0, "group not exisit");
        require(Utils.equalStorage(groupTokenHashMap[groupKey][chainId], Utils.addressToBytes(asset)),"asset not in group");
        require(_transferToContract(asset, amount), "transfer asset from fromAddress to lock_proxy contract  failed!");
        groupBalance[asset][groupKey].add(amount);
        
        emit AddCrossChainLiquidityEvent(_msgSender(), groupKey, asset, amount);
    }
    
    function lock(bytes20 groupKey, address fromAsset, uint amount, bytes memory toAddress, uint64 toChainId) public payable returns(bool){
        require(amount != 0, "amount cannot be zero!");
        require(_transferToContract(fromAsset, amount), "transfer asset from fromAddress to lock_proxy contract  failed!");
        require(Utils.equalStorage(groupTokenHashMap[groupKey][chainId], Utils.addressToBytes(fromAsset)),"fromAsset not in group");
        
        bytes memory toAssetHash = groupTokenHashMap[groupKey][toChainId];
        require(toAssetHash.length != 0, "empty illegal toAssetHash");
        bytes memory txData = abi.encode(groupKey, toAssetHash, toAddress, amount);
        bytes memory toProxyHash = proxyHashMap[toChainId];
        require(toProxyHash.length != 0, "empty illegal toProxyHash");
        
        groupBalance[fromAsset][groupKey].add(amount);
        
        require(IEthCrossChainManager(managerContract).crossChain(toChainId, toProxyHash, "unlock", txData), "EthCrossChainManager crossChain executed error!");
        
        emit LockEvent(groupKey, fromAsset, _msgSender(), toChainId, toAssetHash, toAddress, amount);
        
        return true;
    }
    
    function unlock(bytes memory txData, bytes memory fromContract, uint64 fromChainId) public onlyManagerContract returns(bool) {
        bytes20 groupKey;
        bytes memory toAssetHash;
        bytes memory toAddressHash;
        uint amount;
        (groupKey, toAssetHash, toAddressHash, amount) = abi.decode(txData, (bytes20, bytes, bytes, uint));
        
        require(fromContract.length != 0, "from proxy contract address cannot be empty");
        require(Utils.equalStorage(proxyHashMap[fromChainId], fromContract), "From Proxy contract address error!");
        
        require(Utils.equalStorage(groupTokenHashMap[groupKey][chainId], toAssetHash), "illegal toAssetHash");
        address toAsset = Utils.bytesToAddress(toAssetHash);

        require(toAddressHash.length != 0, "toAddress cannot be empty");
        address toAddress = Utils.bytesToAddress(toAddressHash);
        
        require(groupBalance[toAsset][groupKey] >= amount, "insufficient group balance");
        groupBalance[toAsset][groupKey].sub(amount);
        
        require(_transferFromContract(toAsset, toAddress, amount), "transfer asset from lock_proxy contract to toAddress failed!");
        
        emit UnlockEvent(groupKey, toAsset, toAddress, amount);
        
        return true;
    }
    
    function _deleteGroup(bytes20 groupKey) internal {
        for (uint i=0; i<groupTokenNumMap[groupKey]; i++) {
            delete groupTokenHashMap[groupKey][indexedGroupTokenChainId[groupKey][i]];
            delete indexedGroupTokenChainId[groupKey][i];
        }
        delete groupTokenNumMap[groupKey];
        delete groupOwnerMap[groupKey];
        delete groupCreateChainIdMap[groupKey];
    }
    
    function generateKey(uint64 ownerChainId, bytes memory owner, uint8 num, uint64[] memory chainIds, bytes[] memory addrs) public pure returns(bytes20 key) {
        require(chainIds.length == num, "!chainId array length");
        require(addrs.length == num, "!address array length");
        key = leftRotateForBytes20(ownerChainId, bytesToBytes20(owner));
        for (uint i=0; i<num; i++) {
            key = xorForBytes20(key, leftRotateForBytes20(chainIds[i], bytesToBytes20(addrs[i])));
        }
    }
    
    // right rotate bytes20 for num bytes
    function leftRotateForBytes20(uint64 num, bytes20 raw) internal pure returns(bytes20 res) {
        num %= 20;
        uint[2] memory cache;
        assembly {
            mstore(cache, raw)
            mstore(add(cache,0x14), mload(cache))
            res := mload(add(cache,num))
        }
    }
    
    function xorForBytes20(bytes20 addr1, bytes20 addr2) internal pure returns(bytes20 res) {
        assembly { res := xor(addr1, addr2) }
    }
    
    // This function is used to convert any bytes into 20 bytes format
    function bytesToBytes20(bytes memory raw) internal pure returns(bytes20 res) {
        if (raw.length == 0) {
            assembly { res := raw }
            return res;
        }
        assembly { res := mload(add(raw,0x20)) }
    }
    
    function _transferToContract(address fromAssetHash, uint256 amount) internal returns (bool) {
        if (fromAssetHash == address(0)) {
            // fromAssetHash === address(0) denotes user choose to lock ether
            // passively check if the received msg.value equals amount
            require(msg.value != 0, "transferred ether cannot be zero!");
            require(msg.value == amount, "transferred ether is not equal to amount!");
        } else {
            // make sure lockproxy contract will decline any received ether
            require(msg.value == 0, "there should be no ether transfer!");
            // actively transfer amount of asset from msg.sender to lock_proxy contract
            require(_transferERC20ToContract(fromAssetHash, _msgSender(), address(this), amount), "transfer erc20 asset to lock_proxy contract failed!");
        }
        return true;
    }
    function _transferFromContract(address toAssetHash, address toAddress, uint256 amount) internal returns (bool) {
        if (toAssetHash == address(0x0000000000000000000000000000000000000000)) {
            // toAssetHash === address(0) denotes contract needs to unlock ether to toAddress
            // convert toAddress from 'address' type to 'address payable' type, then actively transfer ether
            address(uint160(toAddress)).transfer(amount);
        } else {
            // actively transfer amount of asset from msg.sender to lock_proxy contract 
            require(_transferERC20FromContract(toAssetHash, toAddress, amount), "transfer erc20 asset to lock_proxy contract failed!");
        }
        return true;
    }
    
    
    function _transferERC20ToContract(address fromAssetHash, address fromAddress, address toAddress, uint256 amount) internal returns (bool) {
         IERC20 erc20Token = IERC20(fromAssetHash);
        //  require(erc20Token.transferFrom(fromAddress, toAddress, amount), "trasnfer ERC20 Token failed!");
         erc20Token.safeTransferFrom(fromAddress, toAddress, amount);
         return true;
    }
    function _transferERC20FromContract(address toAssetHash, address toAddress, uint256 amount) internal returns (bool) {
         IERC20 erc20Token = IERC20(toAssetHash);
        //  require(erc20Token.transfer(toAddress, amount), "trasnfer ERC20 Token failed!");
         erc20Token.safeTransfer(toAddress, amount);
         return true;
    }
    
}