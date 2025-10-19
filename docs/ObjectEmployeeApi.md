# ObjectEmployeeApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**employeeGetListV1**](#employeegetlistv1) | **GET** /1/object/employee/getList | Retrieve Employee list|
|[**employeeImportIntoEDMV1**](#employeeimportintoedmv1) | **POST** /1/object/employee/{pkiEmployeeID}/importIntoEDM | Import attachments into the Employee|

# **employeeGetListV1**
> EmployeeGetListV1Response employeeGetListV1()



### Example

```typescript
import {
    ObjectEmployeeApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEmployeeApi(configuration);

let eOrderBy: 'pkiEmployeeID_ASC' | 'pkiEmployeeID_DESC' | 'fkiDepartmentID_ASC' | 'fkiDepartmentID_DESC' | 'sEmployeeCode_ASC' | 'sEmployeeCode_DESC' | 'sEmployeeInternalcode_ASC' | 'sEmployeeInternalcode_DESC' | 'bEmployeeIsactive_ASC' | 'bEmployeeIsactive_DESC' | 'dtEmployeeHiredate_ASC' | 'dtEmployeeHiredate_DESC' | 'dtEmployeeLeavedate_ASC' | 'dtEmployeeLeavedate_DESC' | 'sDepartmentNameX_ASC' | 'sDepartmentNameX_DESC' | 'sContactFirstname_ASC' | 'sContactFirstname_DESC' | 'sContactLastname_ASC' | 'sContactLastname_DESC' | 'sPhoneE164_ASC' | 'sPhoneE164_DESC' | 'sEmailAddress_ASC' | 'sEmailAddress_DESC' | 'sAddressCivic_ASC' | 'sAddressCivic_DESC' | 'sAddressStreet_ASC' | 'sAddressStreet_DESC' | 'sAddressSuite_ASC' | 'sAddressSuite_DESC' | 'sAddressCity_ASC' | 'sAddressCity_DESC' | 'sAddressZip_ASC' | 'sAddressZip_DESC' | 'sProvinceNameX_ASC' | 'sProvinceNameX_DESC' | 'sCountryNameX_ASC' | 'sCountryNameX_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.employeeGetListV1(
    eOrderBy,
    iRowMax,
    iRowOffset,
    acceptLanguage,
    sFilter
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **eOrderBy** | [**&#39;pkiEmployeeID_ASC&#39; | &#39;pkiEmployeeID_DESC&#39; | &#39;fkiDepartmentID_ASC&#39; | &#39;fkiDepartmentID_DESC&#39; | &#39;sEmployeeCode_ASC&#39; | &#39;sEmployeeCode_DESC&#39; | &#39;sEmployeeInternalcode_ASC&#39; | &#39;sEmployeeInternalcode_DESC&#39; | &#39;bEmployeeIsactive_ASC&#39; | &#39;bEmployeeIsactive_DESC&#39; | &#39;dtEmployeeHiredate_ASC&#39; | &#39;dtEmployeeHiredate_DESC&#39; | &#39;dtEmployeeLeavedate_ASC&#39; | &#39;dtEmployeeLeavedate_DESC&#39; | &#39;sDepartmentNameX_ASC&#39; | &#39;sDepartmentNameX_DESC&#39; | &#39;sContactFirstname_ASC&#39; | &#39;sContactFirstname_DESC&#39; | &#39;sContactLastname_ASC&#39; | &#39;sContactLastname_DESC&#39; | &#39;sPhoneE164_ASC&#39; | &#39;sPhoneE164_DESC&#39; | &#39;sEmailAddress_ASC&#39; | &#39;sEmailAddress_DESC&#39; | &#39;sAddressCivic_ASC&#39; | &#39;sAddressCivic_DESC&#39; | &#39;sAddressStreet_ASC&#39; | &#39;sAddressStreet_DESC&#39; | &#39;sAddressSuite_ASC&#39; | &#39;sAddressSuite_DESC&#39; | &#39;sAddressCity_ASC&#39; | &#39;sAddressCity_DESC&#39; | &#39;sAddressZip_ASC&#39; | &#39;sAddressZip_DESC&#39; | &#39;sProvinceNameX_ASC&#39; | &#39;sProvinceNameX_DESC&#39; | &#39;sCountryNameX_ASC&#39; | &#39;sCountryNameX_DESC&#39;**]**Array<&#39;pkiEmployeeID_ASC&#39; &#124; &#39;pkiEmployeeID_DESC&#39; &#124; &#39;fkiDepartmentID_ASC&#39; &#124; &#39;fkiDepartmentID_DESC&#39; &#124; &#39;sEmployeeCode_ASC&#39; &#124; &#39;sEmployeeCode_DESC&#39; &#124; &#39;sEmployeeInternalcode_ASC&#39; &#124; &#39;sEmployeeInternalcode_DESC&#39; &#124; &#39;bEmployeeIsactive_ASC&#39; &#124; &#39;bEmployeeIsactive_DESC&#39; &#124; &#39;dtEmployeeHiredate_ASC&#39; &#124; &#39;dtEmployeeHiredate_DESC&#39; &#124; &#39;dtEmployeeLeavedate_ASC&#39; &#124; &#39;dtEmployeeLeavedate_DESC&#39; &#124; &#39;sDepartmentNameX_ASC&#39; &#124; &#39;sDepartmentNameX_DESC&#39; &#124; &#39;sContactFirstname_ASC&#39; &#124; &#39;sContactFirstname_DESC&#39; &#124; &#39;sContactLastname_ASC&#39; &#124; &#39;sContactLastname_DESC&#39; &#124; &#39;sPhoneE164_ASC&#39; &#124; &#39;sPhoneE164_DESC&#39; &#124; &#39;sEmailAddress_ASC&#39; &#124; &#39;sEmailAddress_DESC&#39; &#124; &#39;sAddressCivic_ASC&#39; &#124; &#39;sAddressCivic_DESC&#39; &#124; &#39;sAddressStreet_ASC&#39; &#124; &#39;sAddressStreet_DESC&#39; &#124; &#39;sAddressSuite_ASC&#39; &#124; &#39;sAddressSuite_DESC&#39; &#124; &#39;sAddressCity_ASC&#39; &#124; &#39;sAddressCity_DESC&#39; &#124; &#39;sAddressZip_ASC&#39; &#124; &#39;sAddressZip_DESC&#39; &#124; &#39;sProvinceNameX_ASC&#39; &#124; &#39;sProvinceNameX_DESC&#39; &#124; &#39;sCountryNameX_ASC&#39; &#124; &#39;sCountryNameX_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**EmployeeGetListV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/vnd.openxmlformats-officedocument.spreadsheetml.sheet


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **employeeImportIntoEDMV1**
> EmployeeImportIntoEDMV1Response employeeImportIntoEDMV1(employeeImportIntoEDMV1Request)



### Example

```typescript
import {
    ObjectEmployeeApi,
    Configuration,
    EmployeeImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEmployeeApi(configuration);

let pkiEmployeeID: number; // (default to undefined)
let employeeImportIntoEDMV1Request: EmployeeImportIntoEDMV1Request; //

const { status, data } = await apiInstance.employeeImportIntoEDMV1(
    pkiEmployeeID,
    employeeImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **employeeImportIntoEDMV1Request** | **EmployeeImportIntoEDMV1Request**|  | |
| **pkiEmployeeID** | [**number**] |  | defaults to undefined|


### Return type

**EmployeeImportIntoEDMV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

