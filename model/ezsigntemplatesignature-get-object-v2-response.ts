/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
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
import { EzsigntemplatesignatureGetObjectV2ResponseAllOf } from './ezsigntemplatesignature-get-object-v2-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignatureGetObjectV2ResponseMPayload } from './ezsigntemplatesignature-get-object-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplatesignatureGetObjectV2Response
 * Response for GET /2/object/ezsigntemplatesignature/{pkiEzsigntemplatesignatureID}
 * @export
 */
export type EzsigntemplatesignatureGetObjectV2Response = CommonResponse & EzsigntemplatesignatureGetObjectV2ResponseAllOf;


/**
 * @export 
 * A EzsigntemplatesignatureGetObjectV2Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplatesignatureGetObjectV2Response
 */
export class DefaultObjectEzsigntemplatesignatureGetObjectV2Response extends DefaultObject {
   mPayload:Partial<EzsigntemplatesignatureGetObjectV2ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


