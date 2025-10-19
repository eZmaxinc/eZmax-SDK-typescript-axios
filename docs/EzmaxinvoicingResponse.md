# EzmaxinvoicingResponse

A Ezmaxinvoicing Object

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

## Example

```typescript
import { EzmaxinvoicingResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzmaxinvoicingResponse = {
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
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
