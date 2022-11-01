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
import { EzsignbulksendGetEzsignbulksendtransmissionsV1ResponseAllOf } from './ezsignbulksend-get-ezsignbulksendtransmissions-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksendGetEzsignbulksendtransmissionsV1ResponseMPayload } from './ezsignbulksend-get-ezsignbulksendtransmissions-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type EzsignbulksendGetEzsignbulksendtransmissionsV1Response
 * Response for GET /1/object/ezsignbulksend/{pkiEzsignbulksend}/getEzsignbulksendtransmissions
 * @export
 */
export type EzsignbulksendGetEzsignbulksendtransmissionsV1Response = CommonResponse & EzsignbulksendGetEzsignbulksendtransmissionsV1ResponseAllOf;


/**
 * @export 
 * A EzsignbulksendGetEzsignbulksendtransmissionsV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignbulksendGetEzsignbulksendtransmissionsV1Response
 */
export class DefaultObjectEzsignbulksendGetEzsignbulksendtransmissionsV1Response extends DefaultObject {
   mPayload:Partial<EzsignbulksendGetEzsignbulksendtransmissionsV1ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


