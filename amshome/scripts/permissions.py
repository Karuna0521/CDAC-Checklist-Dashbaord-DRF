from rest_framework import permissions, exceptions

from amshome.models import UserGroups

class IsPublicAuthority(permissions.BasePermission):
    def has_permission(self, request, view):
        user = request.user
        try : 
            u_g = UserGroups.objects.get(user_id=user.pk)
        except UserGroups.DoesNotExist:
            return False
        if u_g.group.pk == 4 and request.user.is_authenticated == True:
           return True
        return False

class IsAuditor(permissions.BasePermission):

    def has_permission(self, request, view):
        user = request.user
        try : 
            u_g = UserGroups.objects.get(user_id=user.pk)
        except UserGroups.DoesNotExist:
            return False
        if u_g.group.pk == 2 and request.user.is_authenticated == True:
           return True
        return False



class IsReviewer(permissions.BasePermission):

    def has_permission(self, request, view):
        user = request.user
        try : 
            u_g = UserGroups.objects.get(user_id=user.pk)
        except UserGroups.DoesNotExist:
            return False
        if u_g.group.pk == 3 and request.user.is_authenticated == True:
           return True
        return False
    
class IsAdmin(permissions.BasePermission):
    
    def has_permission(self, request, view):
        user = request.user
        try : 
            u_g = UserGroups.objects.get(user_id=user.pk)
        except UserGroups.DoesNotExist:
            return False
        if u_g.group.pk == 1 and request.user.is_authenticated == True:
           return True
        return False