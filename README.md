# LockProxyGroup
Contact ztj for more details.
But keep in mind: ztj wish you guys to figure it out for yourself.

### 在单链上运行的demo，主要包含如下三个组件：
## ERC20Pro.sol
测试用ERC20合约，实现了mint和burn。
## Hub.sol
测试用的CrossChainManager合约，各个LockProxy向Hub发起调用，经过Hub路由到其他LockProxy合约，模拟跨链的流程。
每个LockProxy要参与跨链，必须在Hub合约中通过bind()函数来绑定。
## LockProxyGroup.sol
demo去中心化上币的LockProxy合约。
construct(): 设置模拟链Id以及Hub合约地址。
setManagerContract(): 设置Hub合约地址。
bindProxyHash(): 绑定其他的LockProxyGroup合约地址。
ownerCreateGroup(): 创建一个Group，创建时会向group内的其他链发送registerGroup请求。参数包括：
  + num: group内token总数。
  + tokenChainIds: group内的token对应的链Id列表，升序排列，不可重复。
  + tokenAddrs: 以tokenChainIds顺序排列的 group内token合约的地址。
registerGroup(): 由发起链的LockProxyGroup合约创建请求，经跨链后，在链上注册相应group。
ownerUpdateGroup(): 升级一个Group，升级时会向group内的其他旧链发送updateGroup请求，向新加入的链发送registerGroup请求，参数包括：
  + oldKey: 需要升级的原始Group key。
  + groupTokenNum: 新group的token总数。
  + tokenChainIds: 新group内的token对应的链Id列表，升序排列，不可重复，并且必须包含原先group的token成员。
  + tokenAddrs: 新group内的token对应的合约地址，必须包含原group内所有token成员。
updateGroup(): 由发起链的LockProxyGroup合约创建请求，经跨链后，在链上升级相应group。
addCrossChainLiquidity(): 向一个Group添加跨链流动性。添加后无法移除。
lock(): 发起跨链，源链锁定一部分资产，包含参数：
  + groupKey: 需要升级的原始Group key。
  + fromAsset: 新group的token总数。
  + amonut: 跨链数额。
  + toAddress: 接受地址。
  + toChainId: 目标链Id。
unlock(): 收到跨链请求，释放一定资产，如果group的余额不足会失败。