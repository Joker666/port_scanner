from robyn import Robyn

app = Robyn(__file__)


@app.post("/api/scan/tcp")
def index():
    return "Hello World!"


if __name__ == "__main__":
    app.serve_directory(route="/", directory_path="./ui/dist", index_file="index.html")
    app.start(host="0.0.0.0", port=8080)
