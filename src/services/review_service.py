from repo.repository import ReviewDAO, ReviewFlowDAO, ReviewStageDAO


class ReviewService:
    """
    提供面向api接口数据的服务函数封装
    """

    def __init__(
        self,
        review_dao: ReviewDAO,
        review_stage_dao: ReviewStageDAO,
        review_flow_dao: ReviewFlowDAO,
    ):
        self.review_dao = review_dao
        self.review_stage_dao = review_stage_dao
        self.review_flow_dao = review_flow_dao
