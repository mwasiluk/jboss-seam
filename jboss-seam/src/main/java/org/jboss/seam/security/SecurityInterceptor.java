package org.jboss.seam.security;

import java.io.Serializable;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.jboss.seam.annotations.intercept.AroundInvoke;
import org.jboss.seam.annotations.intercept.Interceptor;
import org.jboss.seam.annotations.intercept.InterceptorType;
import org.jboss.seam.annotations.security.PermissionCheck;
import org.jboss.seam.annotations.security.Restrict;
import org.jboss.seam.annotations.security.RoleCheck;
import org.jboss.seam.async.AsynchronousInterceptor;
import org.jboss.seam.intercept.AbstractInterceptor;
import org.jboss.seam.intercept.InvocationContext;
import org.jboss.seam.util.Strings;

/**
 * Provides authorization services for component invocations.
 * 
 * @author Shane Bryzak
 */
@Interceptor(type=InterceptorType.CLIENT, 
         around=AsynchronousInterceptor.class)
public class SecurityInterceptor extends AbstractInterceptor implements Serializable
{
   private static final long serialVersionUID = -6567750187000766925L;
   
   /**
    * You may encounter a JVM bug where the field initializer is not evaluated for a transient field after deserialization.
    * @see "http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6252102"
    */
   private transient volatile ConcurrentHashMap<Method, Restriction> restrictions = new ConcurrentHashMap<Method, Restriction>();

   private class Restriction
   {
      private String expression;
      
      private String permissionTarget;
      private String permissionAction;
//
//      private Map<String, Object> methodRestrictions;
//      private Map<Integer,Set<String>> paramRestrictions;
//      private Set<String> roleRestrictions;
            
      public void setExpression(String expression)
      {
         this.expression = expression;
      }
      
      public void setPermissionTarget(String target)
      {
         this.permissionTarget = target;
      }
      
      public void setPermissionAction(String action)
      {
         this.permissionAction = action;
      }
      
//      public void addMethodRestriction(Object target, String action)
//      {
//         if (methodRestrictions == null)
//         {
//            methodRestrictions = new HashMap<String, Object>();
//         }
//
//         methodRestrictions.put(action, target);
//      }
//
//      public void addRoleRestriction(String role)
//      {
//         if (roleRestrictions == null)
//         {
//            roleRestrictions = new HashSet<String>();
//         }
//
//         roleRestrictions.add(role);
//      }
//
//      public void addParameterRestriction(int index, String action)
//      {
//         Set<String> actions = null;
//
//         if (paramRestrictions == null)
//         {
//            paramRestrictions = new HashMap<Integer,Set<String>>();
//         }
//
//         if (!paramRestrictions.containsKey(index))
//         {
//            actions = new HashSet<String>();
//            paramRestrictions.put(index, actions);
//         }
//         else
//         {
//            actions = paramRestrictions.get(index);
//         }
//
//         actions.add(action);
//      }
      
      public void check(Object[] parameters)
      {
         if (Identity.isSecurityEnabled())
         {
            if (expression != null)
            {
               Identity.instance().checkRestriction(expression);
            }
            
//            if (methodRestrictions != null)
//            {
//               for (String action : methodRestrictions.keySet())
//               {
//                  Identity.instance().checkPermission(methodRestrictions.get(action), action);
//               }
//            }
//
//            if (paramRestrictions != null)
//            {
//               for (Integer idx : paramRestrictions.keySet())
//               {
//                  Set<String> actions = paramRestrictions.get(idx);
//                  for (String action : actions)
//                  {
//                     Identity.instance().checkPermission(parameters[idx], action);
//                  }
//               }
//            }
//
//            if (roleRestrictions != null)
//            {
//               for (String role : roleRestrictions)
//               {
//                  Identity.instance().checkRole(role);
//               }
//            }
            
            if (permissionTarget != null && permissionAction != null)
            {
               Identity.instance().checkPermission(permissionTarget, permissionAction);
            }
         }
      }
   }

   @AroundInvoke
   public Object aroundInvoke(InvocationContext invocation) throws Exception
   {
      Method interfaceMethod = invocation.getMethod();
      
      if (!"hashCode".equals(interfaceMethod.getName()))
      {
         Restriction restriction = getRestriction(interfaceMethod);      
         if ( restriction != null ) restriction.check(invocation.getParameters());
      }

      return invocation.proceed();
   }

   private Restriction getRestriction(Method interfaceMethod) throws Exception {
       Restriction restriction = restrictions.get(interfaceMethod);
       if (restriction != null) {
           return restriction;
       }

       Method method = getComponent().getBeanClass().getMethod(
           interfaceMethod.getName(), interfaceMethod.getParameterTypes());

       Restrict restrict = null;
       if (method.isAnnotationPresent(Restrict.class)) {
           restrict = method.getAnnotation(Restrict.class);
       } else if (getComponent().getBeanClass().isAnnotationPresent(Restrict.class)) {
           if (!getComponent().isLifecycleMethod(method)) {
               restrict = getComponent().getBeanClass().getAnnotation(Restrict.class);
           }
       }

       Restriction newRestriction = null;
       if (restrict != null) {
           newRestriction = new Restriction();
           if (Strings.isEmpty(restrict.value())) {
               newRestriction.setPermissionTarget(getComponent().getName());
               newRestriction.setPermissionAction(method.getName());
           } else {
               newRestriction.setExpression(restrict.value());
           }
       }

       // WE DO NOT USE THOSE ANNOTATIONS:

//       for (Annotation annotation : method.getDeclaringClass().getAnnotations()) {
//           if (annotation.annotationType().isAnnotationPresent(RoleCheck.class)) {
//               if (newRestriction == null) newRestriction = new Restriction();
//               newRestriction.addRoleRestriction(annotation.annotationType().getSimpleName().toLowerCase());
//           }
//       }
//
//       for (Annotation annotation : method.getAnnotations()) {
//           if (annotation.annotationType().isAnnotationPresent(PermissionCheck.class)) {
//               PermissionCheck permissionCheck = annotation.annotationType().getAnnotation(PermissionCheck.class);
//
//               Method valueMethod = null;
//               for (Method m : annotation.annotationType().getDeclaredMethods()) {
//                   valueMethod = m;
//                   break;
//               }
//
//               if (valueMethod != null) {
//                   if (newRestriction == null) newRestriction = new Restriction();
//                   Object target = valueMethod.invoke(annotation);
//                   if (!target.equals(void.class)) {
//                       newRestriction.addMethodRestriction(target,
//                           getPermissionAction(permissionCheck, annotation));
//                   }
//               }
//           }
//           if (annotation.annotationType().isAnnotationPresent(RoleCheck.class)) {
//               if (newRestriction == null) newRestriction = new Restriction();
//               newRestriction.addRoleRestriction(annotation.annotationType().getSimpleName().toLowerCase());
//           }
//       }
//
//       for (int i = 0; i < method.getParameterAnnotations().length; i++) {
//           Annotation[] annotations = method.getParameterAnnotations()[i];
//           for (Annotation annotation : annotations) {
//               if (annotation.annotationType().isAnnotationPresent(PermissionCheck.class)) {
//                   PermissionCheck permissionCheck = annotation.annotationType().getAnnotation(PermissionCheck.class);
//                   if (newRestriction == null) newRestriction = new Restriction();
//                   newRestriction.addParameterRestriction(i,
//                       getPermissionAction(permissionCheck, annotation));
//               }
//           }
//       }

       if (newRestriction == null) {
           return null;
       }

       Restriction existing = restrictions.putIfAbsent(interfaceMethod, newRestriction);
       return (existing != null) ? existing : newRestriction;
   }
   
//   private String getPermissionAction(PermissionCheck check, Annotation annotation)
//   {
//      if (!"".equals(check.value()))
//      {
//         return check.value();
//      }
//      else
//      {
//         return annotation.annotationType().getSimpleName().toLowerCase();
//      }
//   }
   
   public boolean isInterceptorEnabled()
   {
      return getComponent().isSecure() && !getComponent().beanClassHasAnnotation("javax.jws.WebService");
   }
}
