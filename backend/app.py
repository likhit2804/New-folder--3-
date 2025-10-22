from aws_cdk import (
    RemovalPolicy,
    Stack,
    aws_lambda as _lambda,
    aws_sqs as sqs,
    aws_dynamodb as dynamodb,
    aws_apigateway as apigateway,
    Duration  # <-- IMPORTED DURATION
)
from constructs import Construct
import aws_cdk as cdk


class TaIacInfraStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # 1️⃣ DynamoDB Table
        table = dynamodb.Table(
            self, "TaIacScanResults-1",
            table_name="TaIacScanResults-1",
            partition_key={"name": "scan_id", "type": dynamodb.AttributeType.STRING},
            removal_policy=RemovalPolicy.DESTROY
        )

        # 2️⃣ SQS Queue
        queue = sqs.Queue(
            self, "TaIacScanQueue-1",
            queue_name="TaIacScanQueue-1"
        )

        # Define the code asset once for both lambdas
        lambda_code_asset = _lambda.Code.from_asset(
            "y",
            bundling={
                "image": _lambda.Runtime.PYTHON_3_11.bundling_image,
                "command": [
                    "bash",
                    "-c",
                    "pip install -r requirements.txt -t /asset-output && cp -r . /asset-output"
                ],
            },
        )

        # 3️⃣ Submitter Lambda
        submitter_lambda = _lambda.Function(
            self, "SubmitterLambda-1",
            function_name="TaIacSubmitter-1",
            runtime=_lambda.Runtime.PYTHON_3_11,
            # CORRECTED: Added the 'lambda.' prefix to the handler path
            handler="lambda.submitter_lambda.lambda_handler",
            code=lambda_code_asset,
            environment={
                "QUEUE_URL": queue.queue_url
            }
        )

        # 4️⃣ Worker Lambda
        worker_lambda = _lambda.Function(
            self, "WorkerLambda-1",
            function_name="TaIacWorker-1",
            runtime=_lambda.Runtime.PYTHON_3_11,
            # CORRECTED: Added the 'lambda.' prefix to the handler path
            handler="lambda.worker_lambda.lambda_handler",
            code=lambda_code_asset,
            # CORRECTED: Added timeout for external API calls
            timeout=Duration.seconds(30),
            environment={
                "TABLE_NAME": table.table_name
            }
        )

        # 5️⃣ Give Lambdas permissions
        queue.grant_send_messages(submitter_lambda)
        queue.grant_consume_messages(worker_lambda)
        table.grant_write_data(worker_lambda)

        # 6️⃣ Connect SQS to Worker Lambda
        worker_lambda.add_event_source_mapping(
            "SQSTrigger-1",
            event_source_arn=queue.queue_arn,
            batch_size=1
        )

        # 7️⃣ API Gateway
        api = apigateway.LambdaRestApi(
            self, "TaIacAPI-1",
            handler=submitter_lambda,
            proxy=False,
            default_cors_preflight_options=apigateway.CorsOptions(
                allow_origins=apigateway.Cors.ALL_ORIGINS,
                allow_methods=apigateway.Cors.ALL_METHODS,
                allow_headers=["Content-Type", "X-Amz-Date", "Authorization", "X-Api-Key"]
            )
        )

        scans = api.root.add_resource("scan")
        scans.add_method("POST")


app = cdk.App()
stack = TaIacInfraStack(app, "TaIacInfraStack-1")
app.synth()