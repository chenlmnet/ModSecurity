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


#ifndef SRC_RULE_WITH_ACTIONS_PROPERTIES_H_
#define SRC_RULE_WITH_ACTIONS_PROPERTIES_H_


#include "modsecurity/transaction.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/variable_value.h"
#include "modsecurity/rule.h"
#include "modsecurity/actions/action.h"
#include "src/actions/action_type_rule_metadata.h"
#include "src/actions/action_with_execution.h"
#include "src/actions/disruptive/disruptive_action.h"

namespace modsecurity {

namespace actions {
class Action;
class Severity;
class LogData;
class Msg;
class Rev;
class SetVar;
class Tag;
class XmlNS;
namespace transformations {
class Transformation;
}
}

using Transformation = actions::transformations::Transformation;
using Transformations = std::vector<std::shared_ptr<Transformation>>;
using TransformationsPtr = std::vector<Transformation *>;

using Action = actions::Action;
using Actions = std::vector<std::shared_ptr<Action>>;

using ActionWithExecution = actions::ActionWithExecution;
using ActionTypeRuleMetaData = actions::ActionTypeRuleMetaData;
using ActionDisruptive = actions::disruptive::ActionDisruptive;

using MatchActions = std::vector<std::shared_ptr<ActionWithExecution > >;
using MatchActionsPtr = std::vector<ActionWithExecution *>;

using Tags = std::vector<std::shared_ptr<actions::Tag> >;
using TagsPtr = std::vector<actions::Tag *>;

using SetVars = std::vector<std::shared_ptr<actions::SetVar> >;
using SetVarsPtr = std::vector<actions::SetVar *>;

using XmlNSs = std::vector<std::shared_ptr<actions::XmlNS> >;
using XmlNSsPtr = std::vector<actions::XmlNS *>;


class RuleWithActionsProperties {
 public:
    int SEVERITY_NOT_SET = 10;
    int ACCURACY_NOT_SET = 10;
    int MATURITY_NOT_SET = 10;

    RuleWithActionsProperties(Transformations *transformations = nullptr) :
        m_actionsRuntimePos(),
        m_actionsSetVar(),
        m_actionsTag(),
        m_actionDisruptiveAction(nullptr),
        m_containsAuditLogAction(false),
        m_containsLogAction(false),
        m_containsMultiMatchAction(false),
        m_containsNoAuditLogAction(false),
        m_containsNoLogAction(false),
        m_containsStaticBlockAction(false),
        m_transformations(transformations != nullptr ? *transformations : Transformations())
    { };

    RuleWithActionsProperties(const RuleWithActionsProperties &o);

    RuleWithActionsProperties &operator=(const RuleWithActionsProperties &o) {
        m_actionsRuntimePos = o.m_actionsRuntimePos;
        m_actionsSetVar = o.m_actionsSetVar;
        m_actionsTag = o.m_actionsTag;
        m_actionDisruptiveAction = o.m_actionDisruptiveAction;
        m_containsAuditLogAction = o.m_containsAuditLogAction;
        m_containsLogAction = o.m_containsLogAction;
        m_containsMultiMatchAction = o.m_containsMultiMatchAction;
        m_containsNoAuditLogAction = o.m_containsNoAuditLogAction;
        m_containsNoLogAction = o.m_containsNoAuditLogAction;
        m_containsStaticBlockAction = o.m_containsStaticBlockAction;
        m_transformations = o.m_transformations;

        return *this;
    };

    void clear() {
        m_containsLogAction = false;
        m_containsNoLogAction = false;
        m_containsStaticBlockAction = false;
        m_actionsSetVar.clear();
        m_actionsTag.clear();
        m_actionsRuntimePos.clear();
        m_actionDisruptiveAction = nullptr;
        m_actionsRuntimePos.clear();
        m_transformations.clear();
    };

    void populate(const RuleWithActions *r);

    /* m_transformations */
    //inline Transformations::const_iterator getTransformations() const noexcept {
    //    return m_transformations.begin();
    //}

 public:
    MatchActions m_actionsRuntimePos;
    SetVars m_actionsSetVar;
    Tags m_actionsTag;
    std::shared_ptr<ActionDisruptive> m_actionDisruptiveAction;
    bool m_containsAuditLogAction:1;
    bool m_containsLogAction:1;
    bool m_containsMultiMatchAction:1;
    bool m_containsNoAuditLogAction:1;
    bool m_containsNoLogAction:1;
    bool m_containsStaticBlockAction:1;


    Transformations m_transformations;
};

}  // namespace modsecurity


#endif  // SRC_RULE_WITH_ACTIONS_PROPERTIES_H_