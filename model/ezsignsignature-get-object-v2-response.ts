/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
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
import { EzsignsignatureGetObjectV2ResponseAllOf } from './ezsignsignature-get-object-v2-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignatureGetObjectV2ResponseMPayload } from './ezsignsignature-get-object-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type EzsignsignatureGetObjectV2Response
 * Response for GET /2/object/ezsignsignature/{pkiEzsignsignatureID}
 * @export
 */
export type EzsignsignatureGetObjectV2Response = CommonResponse & EzsignsignatureGetObjectV2ResponseAllOf;


/**
 * @export 
 * A EzsignsignatureGetObjectV2Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignsignatureGetObjectV2Response
 */
export class DefaultObjectEzsignsignatureGetObjectV2Response extends DefaultObject {
   mPayload:Partial<EzsignsignatureGetObjectV2ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}

