/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import { EzmaxinvoicingGetObjectV2ResponseMPayload } from './ezmaxinvoicing-get-object-v2-response-mpayload';

/**
 * @type EzmaxinvoicingGetObjectV2Response
 * Response for GET /2/object/ezmaxinvoicing/{pkiEzmaxinvoicingID}
 * @export
 */
export type EzmaxinvoicingGetObjectV2Response = CommonResponse;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { DataObjectEzmaxinvoicingGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzmaxinvoicingGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A EzmaxinvoicingGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzmaxinvoicingGetObjectV2Response
 */
export class DataObjectEzmaxinvoicingGetObjectV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzmaxinvoicingGetObjectV2ResponseMPayload = new DataObjectEzmaxinvoicingGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A EzmaxinvoicingGetObjectV2Response Validation Object
 * @class ValidationObjectEzmaxinvoicingGetObjectV2Response
 */
export class ValidationObjectEzmaxinvoicingGetObjectV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzmaxinvoicingGetObjectV2ResponseMPayload()
} 


