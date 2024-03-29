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
import { EzsigntemplatepackagemembershipGetObjectV2ResponseAllOf } from './ezsigntemplatepackagemembership-get-object-v2-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackagemembershipGetObjectV2ResponseMPayload } from './ezsigntemplatepackagemembership-get-object-v2-response-mpayload';

/**
 * @type EzsigntemplatepackagemembershipGetObjectV2Response
 * Response for GET /2/object/ezsigntemplatepackagemembership/{pkiEzsigntemplatepackagemembershipID}
 * @export
 */
export type EzsigntemplatepackagemembershipGetObjectV2Response = CommonResponse & EzsigntemplatepackagemembershipGetObjectV2ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplatepackagemembershipGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepackagemembershipGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsigntemplatepackagemembershipGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagemembershipGetObjectV2Response
 */
export class DataObjectEzsigntemplatepackagemembershipGetObjectV2Response {
    mPayload:EzsigntemplatepackagemembershipGetObjectV2ResponseMPayload = new DataObjectEzsigntemplatepackagemembershipGetObjectV2ResponseMPayload()
    objDebugPayload?:CommonResponseObjDebugPayload = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsigntemplatepackagemembershipGetObjectV2Response Validation Object
 * @class ValidationObjectEzsigntemplatepackagemembershipGetObjectV2Response
 */
export class ValidationObjectEzsigntemplatepackagemembershipGetObjectV2Response {
   mPayload = new ValidationObjectEzsigntemplatepackagemembershipGetObjectV2ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


