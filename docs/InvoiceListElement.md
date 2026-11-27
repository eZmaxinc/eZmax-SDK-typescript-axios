# InvoiceListElement

A Invoice List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiInvoiceID** | **number** | The unique ID of the Invoice. | [default to undefined]
**fkiAgentID** | **number** | The unique ID of the Agent. | [optional] [default to undefined]
**fkiBrokerID** | **number** | The unique ID of the Broker. | [optional] [default to undefined]
**fkiCustomerID** | **number** | The unique ID of the Customer. | [optional] [default to undefined]
**fkiPeriodID** | **number** | The unique ID of the Period | [default to undefined]
**sPeriodYYYYMM** | **string** | The YYYYMM of the Period | [optional] [default to undefined]
**bInvoiceIspaid** | **boolean** | Whether if it\&#39;s an ispaid | [default to undefined]
**dInvoiceTotal** | **string** | The total of the Invoice | [default to undefined]
**dInvoicePaid** | **string** | The paid of the Invoice | [default to undefined]
**dInvoiceBalance** | **string** | The balance of the Invoice | [optional] [default to undefined]
**dtInvoiceDate** | **string** | The date of the Invoice | [default to undefined]
**eInvoiceType** | [**FieldEInvoiceType**](FieldEInvoiceType.md) |  | [default to undefined]
**sInvoiceNumber** | **string** | The number of Invoice | [optional] [default to undefined]
**sInvoiceRecipient** | **string** | The recipient of Invoice | [optional] [default to undefined]

## Example

```typescript
import { InvoiceListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: InvoiceListElement = {
    pkiInvoiceID,
    fkiAgentID,
    fkiBrokerID,
    fkiCustomerID,
    fkiPeriodID,
    sPeriodYYYYMM,
    bInvoiceIspaid,
    dInvoiceTotal,
    dInvoicePaid,
    dInvoiceBalance,
    dtInvoiceDate,
    eInvoiceType,
    sInvoiceNumber,
    sInvoiceRecipient,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
