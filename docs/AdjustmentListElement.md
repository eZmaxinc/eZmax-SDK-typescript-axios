# AdjustmentListElement

A Adjustment List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiAdjustmentID** | **number** | The unique ID of the Adjustment | [default to undefined]
**fkiPeriodID** | **number** | The unique ID of the Period | [default to undefined]
**sPeriodYYYYMM** | **string** | The YYYYMM of the Period | [optional] [default to undefined]
**fkiUserIDCreated** | **number** | The unique ID of the User | [optional] [default to undefined]
**sUserLoginname** | **string** | The login name of the User. | [optional] [default to undefined]
**dtAdjustmentDate** | **string** | The date of the Adjustment | [default to undefined]
**sAdjustmentNumber** | **string** | The number of the Adjustment | [default to undefined]
**sAdjustmentComment** | **string** | The comment of the Adjustment | [default to undefined]
**dAdjustmentTotaldebit** | **string** | The total debit of Adjustment | [optional] [default to undefined]
**dAdjustmentTotalcredit** | **string** | The total credit of Adjustment | [optional] [default to undefined]

## Example

```typescript
import { AdjustmentListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: AdjustmentListElement = {
    pkiAdjustmentID,
    fkiPeriodID,
    sPeriodYYYYMM,
    fkiUserIDCreated,
    sUserLoginname,
    dtAdjustmentDate,
    sAdjustmentNumber,
    sAdjustmentComment,
    dAdjustmentTotaldebit,
    dAdjustmentTotalcredit,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
