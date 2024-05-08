from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        arg1 = request.form['arg1']
        arg2 = request.form['arg2']
        arg3 = request.form['arg3']
        arg4 = request.form['arg4']
        arg5 = request.form['arg5']
        args = [arg1, arg2, arg3, arg4, arg5]
        output = run_script(args)
        return render_template('index.html', output=output)
    return render_template('index.html')

def run_script(args):
    # 这里编写你的 Python 脚本代码
    # 使用 args 作为参数运行脚本
    # 捕获脚本的输出并返回
    output = f"使用参数: {', '.join(args)} 运行脚本\n"
    output += "这是一个示例输出。\n"
    output += "你可以修改 run_script 函数来运行你的实际脚本。\n"
    return output

if __name__ == '__main__':
    app.run(debug=True)