# EzmaxinvoicingGetProvisionalV1ResponseMPayload

Payload for GET /1/object/ezmaxinvoicing/getProvisional

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzmaxinvoicingID** | **number** | The unique ID of the Ezmaxinvoicing | [optional] [default to undefined]
**fkiEzmaxinvoicingcontractID** | **number** | The unique ID of the Ezmaxinvoicingcontract | [default to undefined]
**fkiEzmaxpricingID** | **number** | The unique ID of the Ezmaxpricing | [default to undefined]
**fkiSystemconfigurationtypeID** | **number** | The unique ID of the Systemconfigurationtype | [default to undefined]
**sSystemconfigurationtypeDescriptionX** | **string** | The description of the Systemconfigurationtype in the language of the requester | [default to undefined]
**yyyymmEzmaxinvoicing** | **string** | The YYYYMM period of the Ezmaxinvoicing | [default to undefined]
**iEzmaxinvoicingDays** | **number** | The number of days invoiced | [default to undefined]
**eEzmaxinvoicingPaymenttype** | [**FieldEEzmaxinvoicingPaymenttype**](FieldEEzmaxinvoicingPaymenttype.md) |  | [default to undefined]
**dEzmaxinvoicingRebatepaymenttype** | **string** | The percentage of rebate depending of the payment type | [default to undefined]
**iEzmaxinvoicingContractlength** | **number** | The length of the contract in years | [default to undefined]
**dEzmaxinvoicingRebatecontractlength** | **string** | The percentage of rebate depending of the contract length | [default to undefined]
**bEzmaxinvoicingRebateEzsignallagents** | **boolean** | Whether the rebate for eZsign is for all agents | [default to undefined]
**objAudit** | [**CommonAudit**](CommonAudit.md) |  | [optional] [default to undefined]
**objEzmaxinvoicingcontract** | [**EzmaxinvoicingcontractResponseCompound**](EzmaxinvoicingcontractResponseCompound.md) |  | [default to undefined]
**objEzmaxpricing** | [**CustomEzmaxpricingResponse**](CustomEzmaxpricingResponse.md) |  | [default to undefined]
**a_objEzmaxinvoicingsummaryglobal** | [**Array&lt;EzmaxinvoicingsummaryglobalResponseCompound&gt;**](EzmaxinvoicingsummaryglobalResponseCompound.md) |  | [default to undefined]
**a_objEzmaxinvoicingsummaryexternal** | [**Array&lt;EzmaxinvoicingsummaryexternalResponseCompound&gt;**](EzmaxinvoicingsummaryexternalResponseCompound.md) |  | [default to undefined]
**a_objEzmaxinvoicingsummaryinternal** | [**Array&lt;EzmaxinvoicingsummaryinternalResponseCompound&gt;**](EzmaxinvoicingsummaryinternalResponseCompound.md) |  | [default to undefined]
**a_objEzmaxinvoicingagent** | [**Array&lt;EzmaxinvoicingagentResponseCompound&gt;**](EzmaxinvoicingagentResponseCompound.md) |  | [default to undefined]
**a_objEzmaxinvoicinguser** | [**Array&lt;EzmaxinvoicinguserResponseCompound&gt;**](EzmaxinvoicinguserResponseCompound.md) |  | [default to undefined]
**a_objEzmaxinvoicingezsignfolder** | [**Array&lt;CustomEzmaxinvoicingEzsignfolderResponse&gt;**](CustomEzmaxinvoicingEzsignfolderResponse.md) |  | [default to undefined]
**a_objEzmaxinvoicingezsigndocument** | [**Array&lt;CustomEzmaxinvoicingEzsigndocumentResponse&gt;**](CustomEzmaxinvoicingEzsigndocumentResponse.md) |  | [default to undefined]

## Example

```typescript
import { EzmaxinvoicingGetProvisionalV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzmaxinvoicingGetProvisionalV1ResponseMPayload = {
    pkiEzmaxinvoicingID,
    fkiEzmaxinvoicingcontractID,
    fkiEzmaxpricingID,
    fkiSystemconfigurationtypeID,
    sSystemconfigurationtypeDescriptionX,
    yyyymmEzmaxinvoicing,
    iEzmaxinvoicingDays,
    eEzmaxinvoicingPaymenttype,
    dEzmaxinvoicingRebatepaymenttype,
    iEzmaxinvoicingContractlength,
    dEzmaxinvoicingRebatecontractlength,
    bEzmaxinvoicingRebateEzsignallagents,
    objAudit,
    objEzmaxinvoicingcontract,
    objEzmaxpricing,
    a_objEzmaxinvoicingsummaryglobal,
    a_objEzmaxinvoicingsummaryexternal,
    a_objEzmaxinvoicingsummaryinternal,
    a_objEzmaxinvoicingagent,
    a_objEzmaxinvoicinguser,
    a_objEzmaxinvoicingezsignfolder,
    a_objEzmaxinvoicingezsigndocument,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
