from datetime import datetime, timedelta, timezone
from uuid import UUID
from beanie.operators import In, Eq, And, GT, ElemMatch

from src.repo.models import Review, ReviewFlow, ReviewStage
from src.repo.repository import  ReviewDAO, ReviewFlowDAO, ReviewStageDAO


class ReviewService:
    """
    提供面向api接口数据的服务函数封装
    """

    def __init__(
        self,
        review_dao: ReviewDAO,
        stage_dao: ReviewStageDAO,
        flow_dao: ReviewFlowDAO,
    ):
        self.review_dao = review_dao
        self.stage_dao = stage_dao
        self.flow_dao = flow_dao

    async def get_all_reviews_by_user_id(self, user_id: UUID) -> list[Review] | None:
        """获取用户的所有批注（排除签名字段）"""
        return await self.review_dao.get_many_by_field(
            "PublisherId", user_id, Review.get_exclude_fields()
        )

    async def get_all_reviews_by_stage_id(self, stage_id: UUID) -> list[Review]:
        """获取阶段的所有批注（排除签名字段）"""
        return await self.review_dao.get_many_by_field(
            "BelongId", stage_id, Review.get_exclude_fields()
        )

    async def get_all_reviews_by_flow_id(self, flow_id: UUID) -> list[Review] | None:
        """获取审核流的所有批注（排除签名字段）"""
        return await self.review_dao.get_many_by_field(
            "FinalBelongId", flow_id, Review.get_exclude_fields()
        )

    async def add_review_async(self, review: Review) -> None:
        """添加批注"""
        await self.review_dao.create(review)

    async def get_all_stage_by_flow_id_async(
        self, flow_id: UUID
    ) -> list[ReviewStage]:
        """获取审核流的所有阶段（排除敏感字段）"""
        return await self.stage_dao.get_many_by_field(
            "BelongId", flow_id, ReviewStage.get_exclude_fields()
        )

    async def get_all_stage_by_user_id_async(
        self, user_id: UUID
    ) -> list[ReviewStage]:
        """获取用户创建的所有阶段（排除敏感字段）"""
        return await self.stage_dao.get_many_by_field(
            "PublisherId", user_id, ReviewStage.get_exclude_fields()
        )

    async def get_stages_by_user_id(self, user_id: UUID) -> list[ReviewStage]:
        """获取用户有权限访问的所有阶段（排除敏感字段）"""
        query = ElemMatch(ReviewStage.AuthorizedIds, {"$eq": user_id})
        return await self.stage_dao.find_with_projection(
            query, ReviewStage.get_exclude_fields()
        )

    async def get_all_stage_count_by_user_id_async(
        self, user_id: UUID, completed: bool = False
    ) -> int:
        """获取用户创建阶段的计数"""
        query = And(
            Eq(ReviewStage.PublisherId, user_id), Eq(ReviewStage.Completed, completed)
        )
        return await self.stage_dao.count_documents(query)

    async def add_stage_async(self, stage: ReviewStage) -> None:
        """添加审核阶段"""
        await self.stage_dao.create(stage)

    async def add_stage_pass_record(self, stage_id: UUID, passed: bool) -> None:
        """添加阶段通过记录"""
        stage = await self.stage_dao.get(stage_id)
        if stage:
            if not hasattr(stage, "PassRecord") or stage.PassRecord is None:
                stage.PassRecord = []
            stage.PassRecord.append(passed)
            await stage.save()

    async def set_stage_pass(self, stage_id: UUID, passed: bool) -> None:
        """设置阶段通过状态"""
        stage = await self.stage_dao.get(stage_id)
        if stage:
            stage.Completed = passed
            await stage.save()

    async def set_stage_record(self, stage_id: UUID, passed: bool) -> None:
        """设置阶段记录（同 add_stage_pass_record）"""
        await self.add_stage_pass_record(stage_id, passed)

    async def has_access_right(self, user_id: UUID, stage_id: UUID) -> bool:
        """检查用户是否有阶段访问权限"""
        query = And(
            Eq(ReviewStage.Id, stage_id),
            ElemMatch(ReviewStage.AuthorizedIds, {"$eq": user_id}),
        )
        count = await self.stage_dao.count_documents(query)
        return count > 0

    async def get_file_data(self, stage_id: UUID) -> ReviewStage | None:
        """获取文件数据（包括所有敏感字段）"""
        return await self.stage_dao.get(stage_id)

    async def add_flow_async(self, flow: ReviewFlow) -> None:
        """添加审核流"""
        await self.flow_dao.create(flow)

    async def get_flow_by_id_async(self, flow_id: UUID) -> ReviewFlow | None:
        """根据ID获取审核流（排除签名字段）"""
        return await self.flow_dao.get_with_projection(
            flow_id, ReviewFlow.get_exclude_fields()
        )

    async def get_flow_by_user_id(self, user_id: UUID) -> list[ReviewFlow]:
        """根据用户ID获取评审流"""
        return await self.flow_dao.get_many_by_field("OwnerId", user_id)

    async def get_stage_by_user_id(self, user_id: UUID) -> list[ReviewStage]:
        """根据用户ID获取评审阶段"""
        return await self.stage_dao.get_many_by_field("PublisherId", user_id)

    async def get_all_flow_stage_by_flow_id(self, flow_id: UUID) -> list[ReviewStage]:
        """根据流程ID获取所有阶段"""
        return await self.stage_dao.get_many_by_field("BelongId", flow_id)

    async def get_review_by_stage_id(self, stage_id: UUID) -> list[Review]:
        """根据阶段ID获取评审记录"""
        return await self.review_dao.get_many_by_field("BelongId", stage_id)

    async def add_review(self, review: Review) -> UUID:
        """添加评审记录"""
        result = await self.review_dao.create(review)
        return result.Id

    async def get_all_flows_by_user_id_async(
        self, user_id: UUID
    ) -> list[ReviewFlow] | None:
        """获取用户的所有审核流（排除签名字段）"""
        return await self.flow_dao.get_many_by_field(
            "OwnerId", user_id, ReviewFlow.get_exclude_fields()
        )

    async def get_all_flows_count_by_user_id_async(
        self, user_id: UUID, completed: bool = False
    ) -> int:
        """获取用户审核流的计数"""
        query = And(
            Eq(ReviewFlow.OwnerId, user_id), Eq(ReviewFlow.Completed, completed)
        )
        return await self.flow_dao.count_documents(query)

    # 杂项方法
    async def get_all_reviews_count_by_user_flows_async(self, user_id: UUID) -> int:
        """获取用户所有审核流中最近一周的批注数量"""
        flows = await self.flow_dao.get_many_by_field("OwnerId", user_id)
        flow_ids = [flow.id for flow in flows] if flows else []

        if not flow_ids:
            return 0

        one_week_ago = datetime.now(timezone.utc) - timedelta(days=7)
        query = And(
            In(Review.FinalBelongId, flow_ids), GT(Review.CreatedAt, one_week_ago)
        )
        return await self.review_dao.count_documents(query)
    
