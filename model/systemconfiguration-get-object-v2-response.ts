/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import type { SystemconfigurationGetObjectV2ResponseMPayload } from './systemconfiguration-get-object-v2-response-mpayload';

/**
 * @type SystemconfigurationGetObjectV2Response
 * Response for GET /2/object/systemconfiguration/{pkiSystemconfigurationID}
 * @export
 */
/*export type SystemconfigurationGetObjectV2Response = CommonResponse;*/
export interface SystemconfigurationGetObjectV2Response {
    /**
     * 
     * @type {SystemconfigurationGetObjectV2ResponseMPayload}
     * @memberof SystemconfigurationGetObjectV2Response
     */
    mPayload:SystemconfigurationGetObjectV2ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectSystemconfigurationGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectSystemconfigurationGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A SystemconfigurationGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectSystemconfigurationGetObjectV2Response
 */
export class DataObjectSystemconfigurationGetObjectV2Response {
    mPayload:SystemconfigurationGetObjectV2ResponseMPayload = new DataObjectSystemconfigurationGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A SystemconfigurationGetObjectV2Response Validation Object
 * @class ValidationObjectSystemconfigurationGetObjectV2Response
 */
export class ValidationObjectSystemconfigurationGetObjectV2Response {
   mPayload = new ValidationObjectSystemconfigurationGetObjectV2ResponseMPayload()
} 


