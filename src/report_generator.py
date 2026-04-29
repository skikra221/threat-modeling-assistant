from datetime import datetime
from jinja2 import Environment, FileSystemLoader

def generate_report(app_data, analysis):
    env = Environment(
        loader=FileSystemLoader("templates"),
        autoescape=False
    )

    template = env.get_template("report_template.md")

    return template.render(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
        app=app_data,
        analysis=analysis
    )
