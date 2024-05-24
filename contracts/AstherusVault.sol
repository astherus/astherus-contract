// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";
import "@chainlink/contracts/src/v0.8/shared/interfaces/AggregatorV3Interface.sol";

contract AstherusVault is Initializable, PausableUpgradeable, AccessControlEnumerableUpgradeable, UUPSUpgradeable {

    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    using Address for address payable;
    using SafeERC20 for IERC20;
    using SignatureChecker for address;

    uint8 constant public USD_DECIMALS = 8;
    address constant public NATIVE = address(bytes20(keccak256("NATIVE")));

    event ReceiveETH(address indexed from, address indexed to, uint256 amount);
    event Deposit(address indexed account, address indexed currency, bool isNative, uint256 amount, uint256 broker);
    event WithdrawPaused(address indexed trigger, address indexed currency, uint256 amount, uint256 amountUsd);
    event Withdraw(uint256 indexed id, address indexed to, address indexed currency, bool isNative, uint256 amount);
    event NewSigner(address oldSigner, address newSigner);
    event UpdateHourlyLimit(uint256 oldHourlyLimit, uint256 newHourlyLimit);
    event AddToken(address indexed currency, address indexed priceFeed, bool fixedPrice);
    event RemoveToken(address indexed currency);

    error ZeroAddress();
    error ZeroAmount();

    struct Token {
        address currency;
        address priceFeed;
        uint256 price;
        bool fixedPrice;
        uint8 priceDecimals;
        uint8 currencyDecimals;
    }

    address public signer;
    uint256 public hourlyLimit;
    mapping(address => Token) public supportToken;
    // id => block.number
    mapping(uint256 => uint256) public withdrawHistory;
    // block.timestamp / 1 hours => USD Value
    mapping(uint256 => uint256) public withdrawPerHours;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    receive() external payable {
        if (msg.value > 0) {
            emit ReceiveETH(msg.sender, address(this), msg.value);
        }
    }

    function initialize(address defaultAdmin) initializer public {
        __Pausable_init();
        __AccessControlEnumerable_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, defaultAdmin);
        _grantRole(ADMIN_ROLE, defaultAdmin);
    }

    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    function _authorizeUpgrade(address newImplementation) internal onlyRole(UPGRADER_ROLE) override {}


    function changeSigner(address newSigner) external onlyRole(ADMIN_ROLE) {
        if (newSigner == address(0)) revert ZeroAddress();
        address oldSigner = signer;
        signer = newSigner;
        emit NewSigner(oldSigner, newSigner);
    }

    function updateHourlyLimit(uint256 newHourlyLimit) external onlyRole(ADMIN_ROLE) {
        if (newHourlyLimit == 0) revert ZeroAmount();
        uint256 oldHourlyLimit = hourlyLimit;
        hourlyLimit = newHourlyLimit;
        emit UpdateHourlyLimit(oldHourlyLimit, newHourlyLimit);
    }

    function addToken(
        address currency,
        address priceFeed,
        uint256 price,
        bool fixedPrice,
        uint8 priceDecimals,
        uint8 currencyDecimals
    ) external onlyRole(ADMIN_ROLE) {
        if (currency == address(0)) revert ZeroAddress();
        Token storage token = supportToken[currency];
        token.currency = currency;
        token.fixedPrice = fixedPrice;
        token.priceDecimals = priceDecimals;
        token.currencyDecimals = currencyDecimals;
        if (fixedPrice) {
            token.price = price;
        } else {
            if (priceFeed == address(0)) revert ZeroAddress();
            AggregatorV3Interface oracle = AggregatorV3Interface(priceFeed);
            require(oracle.decimals() == priceDecimals, "Invalid priceDecimals");
            token.priceFeed = priceFeed;
        }

        emit AddToken(currency, priceFeed, fixedPrice);
    }

    function removeToken(address currency) external onlyRole(ADMIN_ROLE) {
        if (currency == address(0)) revert ZeroAddress();
        delete supportToken[currency];
        emit RemoveToken(currency);
    }

    function _transfer(address payable to, bool isNative, address currency, uint256 amount) private {
        if (amount == 0) revert ZeroAmount();
        if (isNative) {
            to.sendValue(amount);
        } else {
            IERC20 token = IERC20(currency);
            require(token.balanceOf(address(this)) >= amount, "not enough currency balance");
            token.safeTransfer(to, amount);
        }
    }

    function deposit(address currency, uint256 amount, uint256 broker) external {
        require(_supportCurrency(currency), "currency not support");
        if (amount == 0) revert ZeroAmount();
        IERC20 erc20 = IERC20(currency);
        // The top-up amount of Burning Coins is based on the amount received in this contract
        uint256 before = erc20.balanceOf(address(this));
        erc20.safeTransferFrom(msg.sender, address(this), amount);
        emit Deposit(msg.sender, currency, false, erc20.balanceOf(address(this)) - before, broker);
    }

    function depositNative(uint256 broker) external payable {
        require(_supportCurrency(NATIVE), "currency not support");
        uint256 amount = msg.value;
        require(amount > 0, "msg.value must be greater than 0");
        emit Deposit(msg.sender, NATIVE, true, amount, broker);
    }

    function withdraw(bytes calldata message, bytes calldata signature) external whenNotPaused {
        require(signer.isValidSignatureNow(MessageHashUtils.toEthSignedMessageHash(keccak256(message)), signature), "only accept truthHolder signed message");
        (uint256 id, address payable to, bool isNative, address currency, uint256 amount, uint256 deadline) =
                            abi.decode(message, (uint256, address, bool, address, uint256, uint256));
        if (isNative) {
            currency = NATIVE;
        }
        require(withdrawHistory[id] == 0, "already withdraw");
        require(_supportCurrency(currency), "currency not support");
        require(block.timestamp < deadline, "already passed deadline");
        uint256 amountUsd = _amountUsd(currency, amount);
        if (amountUsd == 0) revert ZeroAmount();
        uint256 cursor = block.timestamp / 1 hours;
        if (withdrawPerHours[cursor] + amountUsd > hourlyLimit) {
            _pause();
            emit WithdrawPaused(msg.sender, currency, amount, amountUsd);
        } else {
            withdrawHistory[id] = block.number;
            withdrawPerHours[cursor] += amountUsd;
            _transfer(to, isNative, currency, amount);
            emit Withdraw(id, to, currency, isNative, amount);
        }
    }

    function _supportCurrency(address currency) private view returns (bool) {
        return supportToken[currency].currency != address(0);
    }

    function _amountUsd(address currency, uint256 amount) private view returns (uint256) {
        Token memory token = supportToken[currency];
        uint256 price = token.price;
        if (!token.fixedPrice) {
            AggregatorV3Interface oracle = AggregatorV3Interface(token.priceFeed);
            (, int256 price_,,,) = oracle.latestRoundData();
            price = uint256(price_);
        }
        return price * amount * (10 ** USD_DECIMALS) / (10 ** (token.priceDecimals + token.currencyDecimals));
    }

    function balance(address currency) external view returns(uint256) {
        return IERC20(currency).balanceOf(address(this));
    }
}

