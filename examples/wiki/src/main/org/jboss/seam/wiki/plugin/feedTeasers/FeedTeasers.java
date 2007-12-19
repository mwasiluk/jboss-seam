package org.jboss.seam.wiki.plugin.feedTeasers;

import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Observer;
import org.jboss.seam.wiki.core.feeds.FeedDAO;
import org.jboss.seam.wiki.core.model.FeedEntry;
import org.jboss.seam.ScopeType;

import java.io.Serializable;
import java.util.List;

@Name("feedTeasersPlugin")
@Scope(ScopeType.PAGE)
public class FeedTeasers implements Serializable {

    @In
    FeedDAO feedDAO;

    @In
    FeedTeasersPreferences feedTeasersPreferences;

    private List<FeedEntry> teasers;

    public List<FeedEntry> getTeasers() {
        if (teasers  == null) loadTeasers();
        return teasers;
    }

    @Observer("PreferenceComponent.refresh.feedTeasersPreferences")
    public void loadTeasers() {
        teasers =
            feedDAO.findLastFeedEntries(
                feedTeasersPreferences.getFeedIdentifier(),
                feedTeasersPreferences.getNumberOfTeasers().intValue()
            );
    }

}
