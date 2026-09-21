# SalaryListElement

A Salary List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiSalaryID** | **number** | The unique ID of the Salary | [default to undefined]
**fkiPeriodID** | **number** | The unique ID of the Period | [default to undefined]
**fkiSalaryperiodID** | **number** | The unique ID of the Salaryperiod | [default to undefined]
**fkiUSerIDCreated** | **number** | The unique ID of the User | [optional] [default to undefined]
**dtSalaryPaymentdate** | **string** | The paymentdate of the Salary | [default to undefined]
**sSalaryperiod** | **string** | The period in Salaryperiodgroup | [optional] [default to undefined]
**sPeriodYYYYMM** | **string** | The YYYYMM of the Period | [optional] [default to undefined]
**iSalarypreparationCount** | **number** | The count of Salarypreparation. | [optional] [default to undefined]
**dSalarypreparationTotal** | **string** | The total of the Salarypreparation | [optional] [default to undefined]
**dtSalaryperiodStart** | **string** | The start of the Salaryperiod | [optional] [default to undefined]
**dtSalaryperiodEnd** | **string** | The end of the Salaryperiod | [optional] [default to undefined]
**sUserLoginname** | **string** | The login name of the User. | [optional] [default to undefined]
**dtCreatedDate** | **string** | The date and time at which the object was created | [optional] [default to undefined]
**bSalarypreparationIspaid** | **boolean** | Whether if it\&#39;s an ispaid | [optional] [default to undefined]
**iSalaryperiodgroupYear** | **number** | The year of the Salaryperiodgroup | [optional] [default to undefined]

## Example

```typescript
import { SalaryListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: SalaryListElement = {
    pkiSalaryID,
    fkiPeriodID,
    fkiSalaryperiodID,
    fkiUSerIDCreated,
    dtSalaryPaymentdate,
    sSalaryperiod,
    sPeriodYYYYMM,
    iSalarypreparationCount,
    dSalarypreparationTotal,
    dtSalaryperiodStart,
    dtSalaryperiodEnd,
    sUserLoginname,
    dtCreatedDate,
    bSalarypreparationIspaid,
    iSalaryperiodgroupYear,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
