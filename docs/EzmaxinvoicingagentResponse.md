# EzmaxinvoicingagentResponse

A Ezmaxinvoicingagent Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzmaxinvoicingagentID** | **number** | The unique ID of the Ezmaxinvoicingagent | [optional] [default to undefined]
**fkiEzmaxinvoicingID** | **number** | The unique ID of the Ezmaxinvoicing | [optional] [default to undefined]
**fkiBillingentityinternalID** | **number** | The unique ID of the Billingentityinternal. | [default to undefined]
**sBillingentityinternalDescriptionX** | **string** | The description of the Billingentityinternal in the language of the requester | [default to undefined]
**fkiAgentID** | **number** | The unique ID of the Agent. | [optional] [default to undefined]
**fkiBrokerID** | **number** | The unique ID of the Broker. | [optional] [default to undefined]
**iEzmaxinvoicingagentSession** | **number** | The number of sessions | [default to undefined]
**iEzmaxinvoicingagentCloned** | **number** | The number of times this user was cloned | [default to undefined]
**iEzmaxinvoicingagentInvoice** | **number** | The number of invoices | [default to undefined]
**iEzmaxinvoicingagentInscription** | **number** | The number of inscriptions | [default to undefined]
**iEzmaxinvoicingagentInscriptionactive** | **number** | The number of active inscriptions | [default to undefined]
**iEzmaxinvoicingagentSale** | **number** | The number of sales | [default to undefined]
**iEzmaxinvoicingagentOtherincome** | **number** | The number of otherincomes | [default to undefined]
**iEzmaxinvoicingagentCommissioncalculation** | **number** | The number of commission calculations | [default to undefined]
**iEzmaxinvoicingagentEzsigndocument** | **number** | The number of ezsign documents | [default to undefined]
**bEzmaxinvoicingagentEzsignaccount** | **boolean** | Whether the agent has an eZsign account | [default to undefined]
**bEzmaxinvoicingagentBillableezmax** | **boolean** | Whether it is billable for eZmax | [default to undefined]
**eEzmaxinvoicingagentVariationezmax** | [**FieldEEzmaxinvoicingagentVariationezmax**](FieldEEzmaxinvoicingagentVariationezmax.md) |  | [default to undefined]
**bEzmaxinvoicingagentBillableezsign** | **boolean** | Whether it is billable for eZsign | [default to undefined]
**eEzmaxinvoicingagentVariationezsign** | [**FieldEEzmaxinvoicingagentVariationezsign**](FieldEEzmaxinvoicingagentVariationezsign.md) |  | [default to undefined]

## Example

```typescript
import { EzmaxinvoicingagentResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzmaxinvoicingagentResponse = {
    pkiEzmaxinvoicingagentID,
    fkiEzmaxinvoicingID,
    fkiBillingentityinternalID,
    sBillingentityinternalDescriptionX,
    fkiAgentID,
    fkiBrokerID,
    iEzmaxinvoicingagentSession,
    iEzmaxinvoicingagentCloned,
    iEzmaxinvoicingagentInvoice,
    iEzmaxinvoicingagentInscription,
    iEzmaxinvoicingagentInscriptionactive,
    iEzmaxinvoicingagentSale,
    iEzmaxinvoicingagentOtherincome,
    iEzmaxinvoicingagentCommissioncalculation,
    iEzmaxinvoicingagentEzsigndocument,
    bEzmaxinvoicingagentEzsignaccount,
    bEzmaxinvoicingagentBillableezmax,
    eEzmaxinvoicingagentVariationezmax,
    bEzmaxinvoicingagentBillableezsign,
    eEzmaxinvoicingagentVariationezsign,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
