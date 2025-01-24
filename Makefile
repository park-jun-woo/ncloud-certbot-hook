BINARY_NAME=ncloud-certbot-hook
BUILD_PATH=/usr/local/bin
CONFIG_PATH=/etc/ncloud-certbot-hook
CONFIG_FILE=$(CONFIG_PATH)/config.json

all: build install config setup

build:
	go build -o $(BINARY_NAME) $(BINARY_NAME).go

install:
	sudo mv $(BINARY_NAME) $(BUILD_PATH)/
	sudo chmod +x $(BUILD_PATH)/$(BINARY_NAME)

config:
	@if [ ! -d "$(CONFIG_PATH)" ]; then sudo mkdir -p $(CONFIG_PATH); fi
	@if [ ! -f "$(CONFIG_FILE)" ]; then \
		read -p "Enter your NCP Access Key: " ACCESS_KEY; \
		read -p "Enter your NCP Secret Key: " SECRET_KEY; \
		echo '{\n  "access_key": "'$$ACCESS_KEY'",\n  "secret_key": "'$$SECRET_KEY'",\n  "root_ca_path": "/etc/ssl/certs/ISRG_Root_X1.pem",\n  "sleep_time": 30\n}' | sudo tee $(CONFIG_FILE); \
		sudo chown root:root $(CONFIG_FILE); \
		sudo chmod 600 $(CONFIG_FILE); \
	fi

setup:
	sudo apt update
	sudo apt install ca-certificates -y
	sudo update-ca-certificates

clean:
	rm -f $(BINARY_NAME)
