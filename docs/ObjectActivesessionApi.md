# ObjectActivesessionApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**activesessionGenerateFederationTokenV1**](#activesessiongeneratefederationtokenv1) | **POST** /1/object/activesession/generateFederationToken | Generate a federation token|
|[**activesessionGetCurrentV1**](#activesessiongetcurrentv1) | **GET** /1/object/activesession/getCurrent | Get Current Activesession|
|[**activesessionGetCurrentV2**](#activesessiongetcurrentv2) | **GET** /2/object/activesession/getCurrent | Get Current Activesession|
|[**activesessionGetListV1**](#activesessiongetlistv1) | **GET** /1/object/activesession/getList | Retrieve Activesession list|

# **activesessionGenerateFederationTokenV1**
> ActivesessionGenerateFederationTokenV1Response activesessionGenerateFederationTokenV1(activesessionGenerateFederationTokenV1Request)



### Example

```typescript
import {
    ObjectActivesessionApi,
    Configuration,
    ActivesessionGenerateFederationTokenV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectActivesessionApi(configuration);

let activesessionGenerateFederationTokenV1Request: ActivesessionGenerateFederationTokenV1Request; //

const { status, data } = await apiInstance.activesessionGenerateFederationTokenV1(
    activesessionGenerateFederationTokenV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **activesessionGenerateFederationTokenV1Request** | **ActivesessionGenerateFederationTokenV1Request**|  | |


### Return type

**ActivesessionGenerateFederationTokenV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **activesessionGetCurrentV1**
> ActivesessionGetCurrentV1Response activesessionGetCurrentV1()

Retrieve the details about the current activesession

### Example

```typescript
import {
    ObjectActivesessionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectActivesessionApi(configuration);

const { status, data } = await apiInstance.activesessionGetCurrentV1();
```

### Parameters
This endpoint does not have any parameters.


### Return type

**ActivesessionGetCurrentV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | OK |  -  |
|**350** | The user must authenticate before he can continue with this request |  -  |
|**351** | The user is configured with 2FA and needs to validate its phone number before he can continue with this request |  -  |
|**352** | The user is configured with 2FA and needs to answer a Secretquestion before he can continue with this request |  -  |
|**353** | The user must accept clauses before he can continue with this request |  -  |
|**354** | The user\&#39;s computer must be validated before he can continue with this request |  -  |
|**355** | The user must change its password before he can continue with this request |  -  |
|**356** | The user is not running the latest version of the native application. He must valide or update its version before he can continue with this request |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **activesessionGetCurrentV2**
> ActivesessionGetCurrentV2Response activesessionGetCurrentV2()

Retrieve the details about the current activesession

### Example

```typescript
import {
    ObjectActivesessionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectActivesessionApi(configuration);

const { status, data } = await apiInstance.activesessionGetCurrentV2();
```

### Parameters
This endpoint does not have any parameters.


### Return type

**ActivesessionGetCurrentV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | OK |  -  |
|**350** | The user must authenticate before he can continue with this request |  -  |
|**351** | The user is configured with 2FA and needs to validate its phone number before he can continue with this request |  -  |
|**352** | The user is configured with 2FA and needs to answer a Secretquestion before he can continue with this request |  -  |
|**353** | The user must accept clauses before he can continue with this request |  -  |
|**354** | The user\&#39;s computer must be validated before he can continue with this request |  -  |
|**355** | The user must change its password before he can continue with this request |  -  |
|**356** | The user is not running the latest version of the native application. He must valide or update its version before he can continue with this request |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **activesessionGetListV1**
> ActivesessionGetListV1Response activesessionGetListV1()


### Example

```typescript
import {
    ObjectActivesessionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectActivesessionApi(configuration);

let eOrderBy: 'pkiActivesessionID_ASC' | 'pkiActivesessionID_DESC' | 'fkiUserID_ASC' | 'fkiUserID_DESC' | 'fkiComputerID_ASC' | 'fkiComputerID_DESC' | 'fkiCompanyID_ASC' | 'fkiCompanyID_DESC' | 'fkiDepartmentID_ASC' | 'fkiDepartmentID_DESC' | 'sCompanyNameX_ASC' | 'sCompanyNameX_DESC' | 'sDepartmentNameX_ASC' | 'sDepartmentNameX_DESC' | 'sActivesessionLoginname_ASC' | 'sActivesessionLoginname_DESC' | 'sComputerDescription_ASC' | 'sComputerDescription_DESC' | 'dtActivesessionFirsthit_ASC' | 'dtActivesessionFirsthit_DESC' | 'dtActivesessionLasthit_ASC' | 'dtActivesessionLasthit_DESC' | 'sActivesessionIP_ASC' | 'sActivesessionIP_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.activesessionGetListV1(
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
| **eOrderBy** | [**&#39;pkiActivesessionID_ASC&#39; | &#39;pkiActivesessionID_DESC&#39; | &#39;fkiUserID_ASC&#39; | &#39;fkiUserID_DESC&#39; | &#39;fkiComputerID_ASC&#39; | &#39;fkiComputerID_DESC&#39; | &#39;fkiCompanyID_ASC&#39; | &#39;fkiCompanyID_DESC&#39; | &#39;fkiDepartmentID_ASC&#39; | &#39;fkiDepartmentID_DESC&#39; | &#39;sCompanyNameX_ASC&#39; | &#39;sCompanyNameX_DESC&#39; | &#39;sDepartmentNameX_ASC&#39; | &#39;sDepartmentNameX_DESC&#39; | &#39;sActivesessionLoginname_ASC&#39; | &#39;sActivesessionLoginname_DESC&#39; | &#39;sComputerDescription_ASC&#39; | &#39;sComputerDescription_DESC&#39; | &#39;dtActivesessionFirsthit_ASC&#39; | &#39;dtActivesessionFirsthit_DESC&#39; | &#39;dtActivesessionLasthit_ASC&#39; | &#39;dtActivesessionLasthit_DESC&#39; | &#39;sActivesessionIP_ASC&#39; | &#39;sActivesessionIP_DESC&#39;**]**Array<&#39;pkiActivesessionID_ASC&#39; &#124; &#39;pkiActivesessionID_DESC&#39; &#124; &#39;fkiUserID_ASC&#39; &#124; &#39;fkiUserID_DESC&#39; &#124; &#39;fkiComputerID_ASC&#39; &#124; &#39;fkiComputerID_DESC&#39; &#124; &#39;fkiCompanyID_ASC&#39; &#124; &#39;fkiCompanyID_DESC&#39; &#124; &#39;fkiDepartmentID_ASC&#39; &#124; &#39;fkiDepartmentID_DESC&#39; &#124; &#39;sCompanyNameX_ASC&#39; &#124; &#39;sCompanyNameX_DESC&#39; &#124; &#39;sDepartmentNameX_ASC&#39; &#124; &#39;sDepartmentNameX_DESC&#39; &#124; &#39;sActivesessionLoginname_ASC&#39; &#124; &#39;sActivesessionLoginname_DESC&#39; &#124; &#39;sComputerDescription_ASC&#39; &#124; &#39;sComputerDescription_DESC&#39; &#124; &#39;dtActivesessionFirsthit_ASC&#39; &#124; &#39;dtActivesessionFirsthit_DESC&#39; &#124; &#39;dtActivesessionLasthit_ASC&#39; &#124; &#39;dtActivesessionLasthit_DESC&#39; &#124; &#39;sActivesessionIP_ASC&#39; &#124; &#39;sActivesessionIP_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**ActivesessionGetListV1Response**

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

