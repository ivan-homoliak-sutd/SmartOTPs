#include <Arduino.h>

#include "authenticator.h"
#include "qrcode.h"

#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Keypad.h>
#include <SPI.h>
#include <Wire.h>

#define OTP_INDEX_MAX 8192

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64

#define LETTER_WIDTH 5
#define LINE_HEIGHT 10

#define KEYBOARD_ROWS 4
#define KEYBOARD_COLS 3

char keys[KEYBOARD_ROWS][KEYBOARD_COLS] = {
    { '1', '2', '3' },
    { '4', '5', '6' },
    { '7', '8', '9' },
    { '*', '0', '#' }
};

// map array to pins
byte colPins[KEYBOARD_COLS] = { D8, D7, D0 };
byte rowPins[KEYBOARD_ROWS] = { D3, D4, D5, D6 };

#define OLED_RESET -1
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

Keypad keypad = Keypad(makeKeymap(keys), rowPins, colPins, KEYBOARD_ROWS, KEYBOARD_COLS);

void render_menu(void);
void render_input(void);
void render_show(void);
void handle_input(const char key);
void display_qr();
void display_mnemonic_sentence();

// screen to render
enum UI_SCREEN {
    SCREEN_MENU,
    SCREEN_INPUT,
    SCREEN_VIEW
};

// what to render in view screen
enum VIEW_SCREEN_STATE {
    VIEW_TOKEN,
    VIEW_CONFIG
};

// what to render in input screen
enum INPUT_SCREEN_STATE {
    INPUT_VIEW_SECRET,
    INPUT_OTP_INDEX,
    INPUT_NUM_OF_LEAVES,
    INPUT_NUM_OF_SUBLEAVES,
    INPUT_CHAIN_LEN
};

// whether render mnemonic string or qr code
enum VIEW_SECRET {
    VIEW_QR_CODE,
    VIEW_MNEMONIC
};

uint16_t otp_index_input;
uint8_t token_to_display[TOKEN_SIZE];

UI_SCREEN screen = SCREEN_MENU;
VIEW_SCREEN_STATE view_screen_state;
INPUT_SCREEN_STATE input_screen_state;
VIEW_SECRET view_secret;

//default tree configuration
uint16_t chainLen = 1;
uint16_t numOfLeaves = 8;
uint16_t numOfLeavesInSubtree = 8;
uint8_t seed[TOKEN_SIZE];

void setup() {
    Serial.begin(9600);

    // default seed
    // was provided by mr. Homoliak for testing
    seed[0] = 0x27;
    seed[1] = 0xf8;
    seed[2] = 0x77;
    seed[3] = 0x26;
    seed[4] = 0x1b;
    seed[5] = 0xa2;
    seed[6] = 0x9e;
    seed[7] = 0x82;
    seed[8] = 0xb0;
    seed[9] = 0xc8;
    seed[10] = 0x63;
    seed[11] = 0xb9;
    seed[12] = 0x79;
    seed[13] = 0xa1;
    seed[14] = 0xf0;
    seed[15] = 0x75;

    if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3c)) {
        Serial.println(F("SSD1306 allocation failed"));
        for(;;);
    }

    delay(2000);
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(WHITE);
    display.setCursor(0, 10);
    render_menu();
    display.display();
}

void loop() {

    char key = keypad.getKey();

    if (key != 0) {

        display.clearDisplay();

        handle_input(key);

        display.setCursor(0, 10);

        switch (screen) {
            case SCREEN_MENU:
                render_menu();
                break;
            case SCREEN_INPUT:
                render_input();
                break;
            case SCREEN_VIEW:
                render_show();
                break;
            default:
                display.print(key);
                break;
        }

        display.display();
    }
}

void handle_input(const char key) {
    if (screen == SCREEN_MENU) {
        switch (key) {
            case '1':
                screen = SCREEN_INPUT;
                generate_seed();
                input_screen_state = INPUT_NUM_OF_LEAVES;
                break;
            case '2':
                screen = SCREEN_INPUT;
                view_secret = VIEW_MNEMONIC;
                otp_index_input = 0;
                input_screen_state = INPUT_OTP_INDEX;
                break;
            case '3':
                compute_root(token_to_display);
                view_secret = VIEW_MNEMONIC;
                screen = SCREEN_VIEW;
                view_screen_state = VIEW_TOKEN;
                break;
            case '4':
                memcpy(token_to_display, seed, TOKEN_SIZE);
                view_secret = VIEW_MNEMONIC;
                screen = SCREEN_VIEW;
                view_screen_state = VIEW_TOKEN;
                break;
            case '5':
                screen = SCREEN_VIEW;
                view_screen_state = VIEW_CONFIG;
                break;
            break;
        }
    } else if (screen == SCREEN_INPUT) {
        if (input_screen_state == INPUT_NUM_OF_LEAVES) {
            switch (key) {
                case '0':
                    numOfLeaves = 8;
                    break;
                case '1':
                    numOfLeaves = 16;
                    break;
                case '2':
                    numOfLeaves = 32;
                    break;
                case '3':
                    numOfLeaves = 64;
                    break;
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                case '*':
                case '#':
                    return;
            }
            input_screen_state = INPUT_NUM_OF_SUBLEAVES;
        } else if (input_screen_state == INPUT_NUM_OF_SUBLEAVES) {
            switch (key) {
                case '0':
                    numOfLeavesInSubtree = 2;
                    break;
                case '1':
                    numOfLeavesInSubtree = 4;
                    break;
                case '2':
                    numOfLeavesInSubtree = 8;
                    break;
                case '3':
                    numOfLeavesInSubtree = 16;
                    break;
                case '4':
                    numOfLeavesInSubtree = 32;
                    break;
                case '6':
                case '7':
                case '8':
                case '9':
                case '*':
                case '#':
                    return;
            }
            input_screen_state = INPUT_CHAIN_LEN;
        } else if (input_screen_state == INPUT_CHAIN_LEN) {
            switch (key) {
                case '0':
                    chainLen = 1;
                    break;
                case '1':
                    chainLen = 2;
                    break;
                case '2':
                    chainLen = 4;
                    break;
                case '3':
                    chainLen = 8;
                    break;
                case '4':
                    chainLen = 16;
                    break;
                case '5':
                    chainLen = 32;
                    break;
                case '6':
                    chainLen = 64;
                    break;
                case '7':
                    chainLen = 128;
                    break;
                case '8':
                case '9':
                case '*':
                case '#':
                    return;
            }
            screen = SCREEN_MENU;
        } else if (input_screen_state == INPUT_OTP_INDEX) {
            switch (key) {
                case '#':
                    if (otp_index_input == 0) {
                        break;
                    }
                    otp_index_input /= 10;
                    break;
                case '*':
                    screen = SCREEN_VIEW;
                    compute_otp(otp_index_input - 1, token_to_display);
                    view_screen_state = VIEW_TOKEN;
                    break;
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                    otp_index_input *= 10;
                    otp_index_input += key - '0';
                    if (otp_index_input >= OTP_INDEX_MAX) {
                        otp_index_input -= key - '0';
                        otp_index_input /= 10;
                    }
                    break;
            }
        }
    } else if (screen == SCREEN_VIEW) {
        if (view_screen_state == VIEW_TOKEN && view_secret == VIEW_MNEMONIC) {
            view_secret = VIEW_QR_CODE;
        } else {
            screen = SCREEN_MENU;
        }
    }
}

void render_menu(void) {
    display.println("menu");
    display.println("1) configure");
    display.println("2) get OTP");
    display.println("3) show root");
    display.println("4) show seed");
    display.println("5) show config");
}

void render_input(void) {
    switch (input_screen_state) {
        case INPUT_VIEW_SECRET:
            display.println("Select one...");
            display.println("1) mnemonic sentence");
            display.println("2) QR code");
            break;
        case INPUT_OTP_INDEX:
            display.println("Enter index of OTP:");
            display.setCursor(20, 20);
            display.println(otp_index_input);
            break;
        case INPUT_NUM_OF_LEAVES:
            display.println("num of tree leaves:");
            display.println();
            display.println("0) 8");
            display.println("1) 16");
            display.println("2) 32");
            display.println("3) 64");
            break;
        case INPUT_NUM_OF_SUBLEAVES:
            display.println("subtree leaves num:");
            display.println("0) 2    3) 16");
            display.println("1) 4    4) 32");
            display.println("2) 8    5) 64");
            break;
        case INPUT_CHAIN_LEN:
            display.println("length of hash chain:");
            display.println("0) 1    4) 16");
            display.println("1) 2    5) 32");
            display.println("2) 4    6) 64");
            display.println("3) 8    7) 128");
            break;
        default:
            display.print("error ");
            display.print(input_screen_state);
            break;
    }
}

void render_show(void) {
    switch (view_screen_state) {
        case VIEW_CONFIG:
            display.println("config:");
            display.println();
            display.print("leaves: ");
            display.println(numOfLeaves);
            display.print("sub leaves: ");
            display.println(numOfLeavesInSubtree);
            display.print("chain len: ");
            display.print(chainLen);
            break;
        case VIEW_TOKEN:
            if (view_secret == VIEW_QR_CODE) {
                display_qr();
            } else if (view_secret == VIEW_MNEMONIC) {
                display_mnemonic_sentence();
            }
            break;
    }
}

void display_mnemonic_sentence() {
    char const *sentence[MS];
    compute_mnemonic_sentence(token_to_display, sentence);
    display.print(sentence[0]);
    for (uint8_t i = 1; i < MS; i++) {
        display.print(" ");
        display.print(sentence[i]);
    }
}

void display_qr() {
    QRCode qrcode;
    uint8_t qrcodeBytes[qrcode_getBufferSize(1)];
    qrcode_initBytes(&qrcode, qrcodeBytes, 1, ECC_LOW, token_to_display, TOKEN_SIZE);

    for (uint8_t y = 0; y < qrcode.size; y++) {
        for (uint8_t x = 0; x < qrcode.size; x++) {
            if (qrcode_getModule(&qrcode, x, y)) {
                display.drawRect(x * 3, y * 3 + 1, 3, 3, WHITE);
            }
        }
    }
}
