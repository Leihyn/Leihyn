# Chainlink Integration Guide

## Overview

Chainlink provides:
- **Price Feeds**: Decentralized oracle prices
- **VRF**: Verifiable random numbers
- **Automation**: Decentralized keepers
- **CCIP**: Cross-chain messaging
- **Functions**: Off-chain computation

---

## 1. Price Feeds

### Basic Price Feed

```solidity
import {AggregatorV3Interface} from "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

contract PriceConsumer {
    AggregatorV3Interface internal priceFeed;

    constructor(address _priceFeed) {
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    function getLatestPrice() public view returns (int256) {
        (
            uint80 roundId,
            int256 price,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();

        return price;
    }
}
```

### Production-Safe Price Feed

```solidity
contract SafePriceConsumer {
    AggregatorV3Interface public priceFeed;

    uint256 public constant STALENESS_THRESHOLD = 1 hours;
    uint256 public constant PRICE_PRECISION = 1e8;

    error StalePrice();
    error InvalidPrice();
    error IncompleteRound();

    function getLatestPrice() public view returns (uint256) {
        (
            uint80 roundId,
            int256 price,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();

        // Check for stale price
        if (block.timestamp - updatedAt > STALENESS_THRESHOLD) {
            revert StalePrice();
        }

        // Check for valid price
        if (price <= 0) {
            revert InvalidPrice();
        }

        // Check round is complete
        if (answeredInRound < roundId) {
            revert IncompleteRound();
        }

        return uint256(price);
    }

    // Get price with specific decimals
    function getPriceInDecimals(uint8 targetDecimals) public view returns (uint256) {
        uint256 price = getLatestPrice();
        uint8 feedDecimals = priceFeed.decimals();

        if (feedDecimals < targetDecimals) {
            return price * 10**(targetDecimals - feedDecimals);
        } else {
            return price / 10**(feedDecimals - targetDecimals);
        }
    }
}
```

### Common Price Feed Addresses (Ethereum)

```solidity
// Mainnet
address constant ETH_USD = 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419;
address constant BTC_USD = 0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c;
address constant LINK_USD = 0x2c1d072e956AFFC0D435Cb7AC38EF18d24d9127c;
address constant USDC_USD = 0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6;

// Arbitrum
address constant ARB_ETH_USD = 0x639Fe6ab55C921f74e7fac1ee960C0B6293ba612;
address constant ARB_BTC_USD = 0x6ce185860a4963106506C203335A2910827eBa6;

// Base
address constant BASE_ETH_USD = 0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70;
```

---

## 2. VRF (Verifiable Random Function)

### VRF V2.5 Consumer

```solidity
import {VRFConsumerBaseV2Plus} from "@chainlink/contracts/src/v0.8/vrf/dev/VRFConsumerBaseV2Plus.sol";
import {VRFV2PlusClient} from "@chainlink/contracts/src/v0.8/vrf/dev/libraries/VRFV2PlusClient.sol";

contract VRFConsumer is VRFConsumerBaseV2Plus {
    uint256 public subscriptionId;
    bytes32 public keyHash;
    uint32 public callbackGasLimit = 100000;
    uint16 public requestConfirmations = 3;
    uint32 public numWords = 1;

    mapping(uint256 => address) public requestToSender;
    mapping(address => uint256) public userRandomNumber;

    event RandomnessRequested(uint256 requestId, address requester);
    event RandomnessFulfilled(uint256 requestId, uint256 randomWord);

    constructor(
        uint256 _subscriptionId,
        address _vrfCoordinator,
        bytes32 _keyHash
    ) VRFConsumerBaseV2Plus(_vrfCoordinator) {
        subscriptionId = _subscriptionId;
        keyHash = _keyHash;
    }

    function requestRandomness() external returns (uint256 requestId) {
        requestId = s_vrfCoordinator.requestRandomWords(
            VRFV2PlusClient.RandomWordsRequest({
                keyHash: keyHash,
                subId: subscriptionId,
                requestConfirmations: requestConfirmations,
                callbackGasLimit: callbackGasLimit,
                numWords: numWords,
                extraArgs: VRFV2PlusClient._argsToBytes(
                    VRFV2PlusClient.ExtraArgsV1({nativePayment: false})
                )
            })
        );

        requestToSender[requestId] = msg.sender;
        emit RandomnessRequested(requestId, msg.sender);
    }

    function fulfillRandomWords(
        uint256 requestId,
        uint256[] calldata randomWords
    ) internal override {
        address requester = requestToSender[requestId];
        userRandomNumber[requester] = randomWords[0];
        emit RandomnessFulfilled(requestId, randomWords[0]);
    }

    // Get random number in range [min, max]
    function getRandomInRange(uint256 randomValue, uint256 min, uint256 max)
        public pure returns (uint256)
    {
        return (randomValue % (max - min + 1)) + min;
    }
}
```

---

## 3. Automation (Keepers)

### Automation Compatible Contract

```solidity
import {AutomationCompatibleInterface} from "@chainlink/contracts/src/v0.8/automation/interfaces/AutomationCompatibleInterface.sol";

contract AutomatedContract is AutomationCompatibleInterface {
    uint256 public counter;
    uint256 public lastTimestamp;
    uint256 public interval = 1 hours;

    function checkUpkeep(bytes calldata checkData)
        external
        view
        override
        returns (bool upkeepNeeded, bytes memory performData)
    {
        upkeepNeeded = (block.timestamp - lastTimestamp) >= interval;
        performData = checkData;
    }

    function performUpkeep(bytes calldata performData) external override {
        if ((block.timestamp - lastTimestamp) >= interval) {
            lastTimestamp = block.timestamp;
            counter++;
            // Your automated logic here
        }
    }
}
```

### Log Trigger Automation

```solidity
import {ILogAutomation, Log} from "@chainlink/contracts/src/v0.8/automation/interfaces/ILogAutomation.sol";

contract LogTriggeredAutomation is ILogAutomation {
    event ActionTriggered(address indexed user, uint256 amount);

    function checkLog(
        Log calldata log,
        bytes memory checkData
    ) external pure override returns (bool upkeepNeeded, bytes memory performData) {
        // Decode the log data
        (address user, uint256 amount) = abi.decode(log.data, (address, uint256));

        // Check if action should be performed
        upkeepNeeded = amount > 100 ether;
        performData = abi.encode(user, amount);
    }

    function performUpkeep(bytes calldata performData) external override {
        (address user, uint256 amount) = abi.decode(performData, (address, uint256));
        // Perform action
    }
}
```

---

## 4. CCIP (Cross-Chain Interoperability)

### Send Cross-Chain Message

```solidity
import {IRouterClient} from "@chainlink/contracts-ccip/src/v0.8/ccip/interfaces/IRouterClient.sol";
import {Client} from "@chainlink/contracts-ccip/src/v0.8/ccip/libraries/Client.sol";

contract CCIPSender {
    IRouterClient public router;
    address public linkToken;

    function sendMessage(
        uint64 destinationChainSelector,
        address receiver,
        string calldata message
    ) external returns (bytes32 messageId) {
        Client.EVM2AnyMessage memory evm2AnyMessage = Client.EVM2AnyMessage({
            receiver: abi.encode(receiver),
            data: abi.encode(message),
            tokenAmounts: new Client.EVMTokenAmount[](0),
            extraArgs: Client._argsToBytes(
                Client.EVMExtraArgsV1({gasLimit: 200_000})
            ),
            feeToken: linkToken
        });

        uint256 fees = router.getFee(destinationChainSelector, evm2AnyMessage);

        IERC20(linkToken).approve(address(router), fees);

        messageId = router.ccipSend(destinationChainSelector, evm2AnyMessage);
    }
}
```

### Receive Cross-Chain Message

```solidity
import {CCIPReceiver} from "@chainlink/contracts-ccip/src/v0.8/ccip/applications/CCIPReceiver.sol";
import {Client} from "@chainlink/contracts-ccip/src/v0.8/ccip/libraries/Client.sol";

contract CCIPReceiver is CCIPReceiver {
    event MessageReceived(bytes32 messageId, uint64 sourceChain, address sender, string message);

    constructor(address router) CCIPReceiver(router) {}

    function _ccipReceive(
        Client.Any2EVMMessage memory message
    ) internal override {
        bytes32 messageId = message.messageId;
        uint64 sourceChainSelector = message.sourceChainSelector;
        address sender = abi.decode(message.sender, (address));
        string memory text = abi.decode(message.data, (string));

        emit MessageReceived(messageId, sourceChainSelector, sender, text);
    }
}
```

---

## 5. Chain Selectors (CCIP)

```solidity
// Mainnet
uint64 constant ETHEREUM = 5009297550715157269;
uint64 constant ARBITRUM = 4949039107694359620;
uint64 constant OPTIMISM = 3734403246176062136;
uint64 constant POLYGON = 4051577828743386545;
uint64 constant BASE = 15971525489660198786;
uint64 constant AVALANCHE = 6433500567565415381;
uint64 constant BNB = 11344663589394136015;
```

---

## Security Best Practices

1. **Price Feeds**
   - Always check staleness
   - Validate price > 0
   - Use multiple oracles for critical operations
   - Handle decimals correctly

2. **VRF**
   - Don't use pending randomness
   - Ensure callback has enough gas
   - Consider frontrunning of request

3. **Automation**
   - Validate caller is Automation registry
   - Recheck conditions in performUpkeep
   - Handle gas limits carefully

4. **CCIP**
   - Validate source chain and sender
   - Handle failed messages
   - Consider message ordering
