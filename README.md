# 由Lihil构建的后端服务

## 使用 uv

推荐使用 [uv](https://github.com/guyskk/uv) 工具进行项目管理。

`uv` 支持通过 `uv venv` 创建和管理虚拟环境，并可使用 `uv pip` 安装项目依赖。例如：

```bash
uv venv .venv
uv pip install -r requirements.txt
```

使用 `add` 命令管理绑定项目依赖：

```bash
uv add package
uv remove package
```

并通过 `uv sync` 进行同步，`该命令同样用于为初始环境添加全部依赖`。

这样可以确保依赖环境的隔离和一致性，方便项目的开发与部署。

更多用法请参考 [uv 官方文档](https://github.com/guyskk/uv)。

## 配置

Lihil项目使用 [settings.toml] 文件进行配置，详情参考 src/config.py中配置类的设计，也可自行修改和扩展。

详情参考 [Lihil 配置](https://www.lihil.cc/zh/docs/http/config)

## 启动与运行

项目中使用 [uvicorn] 作为服务器。

直接启动 Lihil 项目，命令如下：

```bash
uv run python -m src.main --server.port=8080 --reload
```

或者，推荐使用 `uvicorn` 运行项目：

```bash
uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
```

其中 `src.main` 为项目入口，`--reload` 参数用于热重载，只应在开发环境使用。