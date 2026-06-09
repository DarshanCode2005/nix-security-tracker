from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin

from shared.auth.utils import isadmin


class AdminRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    def test_func(self) -> bool:
        return isadmin(self.request.user)
