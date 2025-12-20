#!/bin/bash
cd "$(dirname "$0")"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # 无颜色

BINARY="geminicli2api"

echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}${BOLD}       Gemini CLI to API Server${NC}"
echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# 检查是否需要编译
need_build=false

if [[ ! -f "$BINARY" ]]; then
    echo -e "${YELLOW}[检测]${NC} 未找到可执行文件，需要编译"
    need_build=true
else
    # 检查源文件是否比二进制文件新
    for src in *.go; do
        if [[ "$src" -nt "$BINARY" ]]; then
            echo -e "${YELLOW}[检测]${NC} 源文件 ${BOLD}$src${NC} 已更新，需要重新编译"
            need_build=true
            break
        fi
    done

    # 检查 go.mod 是否更新
    if [[ "go.mod" -nt "$BINARY" ]]; then
        echo -e "${YELLOW}[检测]${NC} ${BOLD}go.mod${NC} 已更新，需要重新编译"
        need_build=true
    fi
fi

if $need_build; then
    echo -e "${BLUE}[编译]${NC} 正在编译..."
    if go build -o "$BINARY" .; then
        echo -e "${GREEN}[编译]${NC} 编译成功 ${GREEN}✓${NC}"
    else
        echo -e "${RED}[错误]${NC} 编译失败 ${RED}✗${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}[检测]${NC} 二进制文件是最新的，跳过编译 ${GREEN}✓${NC}"
fi

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}[启动]${NC} 服务器运行在端口 ${BOLD}${PORT:-8888}${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

exec ./"$BINARY"
