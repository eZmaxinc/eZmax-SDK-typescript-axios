/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
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
import { EzsigntemplatepackagemembershipCreateObjectV1ResponseAllOf } from './ezsigntemplatepackagemembership-create-object-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackagemembershipCreateObjectV1ResponseMPayload } from './ezsigntemplatepackagemembership-create-object-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplatepackagemembershipCreateObjectV1Response
 * Response for POST /1/object/ezsigntemplatepackagemembership
 * @export
 */
export type EzsigntemplatepackagemembershipCreateObjectV1Response = CommonResponse & EzsigntemplatepackagemembershipCreateObjectV1ResponseAllOf;


/**
 * @export 
 * A EzsigntemplatepackagemembershipCreateObjectV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplatepackagemembershipCreateObjectV1Response
 */
export class DefaultObjectEzsigntemplatepackagemembershipCreateObjectV1Response extends DefaultObject {
   mPayload:Partial<EzsigntemplatepackagemembershipCreateObjectV1ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


