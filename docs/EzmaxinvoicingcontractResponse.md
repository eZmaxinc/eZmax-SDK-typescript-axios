# EzmaxinvoicingcontractResponse

A Ezmaxinvoicingcontract Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzmaxinvoicingcontractID** | **number** | The unique ID of the Ezmaxinvoicingcontract | [default to undefined]
**eEzmaxinvoicingcontractPaymenttype** | [**FieldEEzmaxinvoicingcontractPaymenttype**](FieldEEzmaxinvoicingcontractPaymenttype.md) |  | [default to undefined]
**iEzmaxinvoicingcontractLength** | **number** | The length in years of the Ezmaxinvoicingcontract | [default to undefined]
**dtEzmaxinvoicingcontractStart** | **string** | The start date of the Ezmaxinvoicingcontract | [default to undefined]
**dtEzmaxinvoicingcontractEnd** | **string** | The end date of the Ezmaxinvoicingcontract | [default to undefined]
**dEzmaxinvoicingcontractLicense** | **string** | The price of the license | [default to undefined]
**dEzmaxinvoicingcontract121qa** | **string** | The price for 121QA | [default to undefined]
**bEzmaxinvoicingcontractEzsignallagents** | **boolean** | Whether eZsign is for all agents | [default to undefined]
**objAudit** | [**CommonAudit**](CommonAudit.md) |  | [default to undefined]

## Example

```typescript
import { EzmaxinvoicingcontractResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzmaxinvoicingcontractResponse = {
    pkiEzmaxinvoicingcontractID,
    eEzmaxinvoicingcontractPaymenttype,
    iEzmaxinvoicingcontractLength,
    dtEzmaxinvoicingcontractStart,
    dtEzmaxinvoicingcontractEnd,
    dEzmaxinvoicingcontractLicense,
    dEzmaxinvoicingcontract121qa,
    bEzmaxinvoicingcontractEzsignallagents,
    objAudit,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
