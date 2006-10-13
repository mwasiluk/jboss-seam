package org.jboss.seam.framework;

import java.util.List;
import java.util.Map;

import javax.persistence.EntityManager;

import org.jboss.seam.annotations.Transactional;
import org.jboss.seam.core.Expressions.ValueBinding;

public class EntityQuery extends Query
{
   private EntityManager entityManager;

   private List resultList;
   private Object singleResult;
   private Long resultCount;
   private Map<String, String> hints;

   @Override
   public void validate()
   {
      super.validate();
      if ( getEntityManager()==null )
      {
         throw new IllegalStateException("entityManager is null");
      }
   }

   @Transactional
   @Override
   public List getResultList()
   {
      if (resultList==null)
      {
         javax.persistence.Query query = createQuery();
         resultList = query==null ? null : query.getResultList();
      }
      return resultList;
   }
   
   @Transactional
   @Override
   public Object getSingleResult()
   {
      if (singleResult==null)
      {
         javax.persistence.Query query = createQuery();
         singleResult = query==null ? 
               null : query.getSingleResult();
      }
      return singleResult;
   }

   @Transactional
   @Override
   public Long getResultCount()
   {
      if (resultCount==null)
      {
         javax.persistence.Query query = createCountQuery();
         resultCount = query==null ? 
               null : (Long) query.getSingleResult();
      }
      return (Long) resultCount;
   }

   @Override
   public void refresh()
   {
      super.refresh();
      resultCount = null;
      resultList = null;
      singleResult = null;
   }
   
   public EntityManager getEntityManager()
   {
      return entityManager;
   }

   public void setEntityManager(EntityManager entityManager)
   {
      this.entityManager = entityManager;
   }

   protected javax.persistence.Query createQuery()
   {
      parseEjbql();
      
      getEntityManager().joinTransaction();
      javax.persistence.Query query = getEntityManager().createQuery( getRenderedEjbql() );
      setParameters( query, getQueryParameters(), 0 );
      setParameters( query, getRestrictionParameters(), getQueryParameters().size() );
      if ( getFirstResult()!=null) query.setFirstResult( getFirstResult() );
      if ( getMaxResults()!=null) query.setMaxResults( getMaxResults() );
      if ( getHints()!=null )
      {
         for ( Map.Entry<String, String> me: getHints().entrySet() )
         {
            query.setHint(me.getKey(), me.getValue());
         }
      }
      return query;
   }
   
   protected javax.persistence.Query createCountQuery()
   {
      parseEjbql();
      
      getEntityManager().joinTransaction();
      javax.persistence.Query query = getEntityManager().createQuery( getCountEjbql() );
      setParameters( query, getQueryParameters(), 0 );
      setParameters( query, getRestrictionParameters(), getQueryParameters().size() );
      return query;
   }

   private void setParameters(javax.persistence.Query query, List<ValueBinding> parameters, int start)
   {
      for (int i=0; i<parameters.size(); i++)
      {
         Object parameterValue = parameters.get(i).getValue();
         if (parameterValue!=null)
         {
            query.setParameter( "p" + start++, parameterValue );
         }
      }
   }

   public Map<String, String> getHints()
   {
      return hints;
   }

   public void setHints(Map<String, String> hints)
   {
      this.hints = hints;
   }

}
