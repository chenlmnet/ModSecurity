/*
 * ModSecurity, http://www.modsecurity.org/
 * Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */

#include "modsecurity/rule.h"

#include <stdio.h>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <list>
#include <memory>
#include <string>
#include <utility>

#include "modsecurity/actions/action.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/rule_message.h"
#include "modsecurity/rules_set.h"
#include "src/rule_with_actions.h"
#include "src/actions/accuracy.h"
#include "src/actions/block.h"
#include "src/actions/capture.h"
#include "src/actions/log_data.h"
#include "src/actions/msg.h"
#include "src/actions/maturity.h"
#include "src/actions/multi_match.h"
#include "src/actions/rev.h"
#include "src/actions/log.h"
#include "src/actions/no_log.h"
#include "src/actions/set_var.h"
#include "src/actions/severity.h"
#include "src/actions/tag.h"
#include "src/actions/disruptive/disruptive_action.h"
#include "src/actions/transformations/transformation.h"
#include "src/actions/transformations/none.h"
#include "src/actions/xmlns.h"
#include "src/utils/string.h"
#include "src/actions/action_with_run_time_string.h"
#include "src/actions/phase.h"
#include "src/actions/chain.h"
#include "src/actions/rule_id.h"
#include "src/actions/ver.h"
#include "src/actions/action_type_rule_metadata.h"
#include "src/actions/action_allowed_in_sec_default_action.h"


namespace modsecurity {

void RuleWithActionsProperties::populate(const RuleWithActions *r) {
    // FIXME: Populate the rest of the stuff.
    for (auto i : m_actionsSetVar) {
        /**
         *
         * ActionWithRunTimeString needs to be aware of the Rule that it
         * belongs to. It is necessary to resolve some variables
         * (e.g. Rule); Clone and associate are mandatory.
         *
         */
        actions::ActionWithRunTimeString *arts = dynamic_cast<actions::ActionWithRunTimeString *>(i.get());
        if (arts != nullptr) {
            arts->populate(r);
        }
    }
}


RuleWithActionsProperties::RuleWithActionsProperties(const RuleWithActionsProperties &o) :
    m_actionsRuntimePos(o.m_actionsRuntimePos),
    //m_actionsSetVar(o.m_actionsSetVar),
    m_actionsSetVar(),
    m_actionsTag(o.m_actionsTag),
    m_actionDisruptiveAction(o.m_actionDisruptiveAction),
    m_containsAuditLogAction(o.m_containsAuditLogAction),
    m_containsLogAction(o.m_containsLogAction),
    m_containsMultiMatchAction(o.m_containsMultiMatchAction),
    m_containsNoAuditLogAction(o.m_containsNoAuditLogAction),
    m_containsNoLogAction(o.m_containsNoAuditLogAction),
    m_containsStaticBlockAction(o.m_containsStaticBlockAction),
    m_transformations(o.m_transformations)
{
    // TODO: Copy the rest of the stuff.
    for (auto i : o.m_actionsSetVar) {
        actions::ActionWithRunTimeString *arts = dynamic_cast<actions::ActionWithRunTimeString *>(i.get());
        if (!arts) {
            Action *a = i->clone();
            actions::SetVar *aa = dynamic_cast<actions::SetVar *>(a);
            aa->populate(nullptr);
            m_actionsSetVar.push_back(std::make_shared<actions::SetVar>(*aa));
            continue;
        }
        m_actionsSetVar.push_back(i);
    }
};


}  // namespace modsecurity
