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
import { CommonGetListV1ResponseMPayload } from './common-get-list-v1-response-mpayload';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackageGetListV1ResponseMPayloadAllOf } from './ezsigntemplatepackage-get-list-v1-response-mpayload-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackageListElement } from './ezsigntemplatepackage-list-element';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplatepackageGetListV1ResponseMPayload
 * Payload for GET /1/object/ezsigntemplatepackage/getList
 * @export
 */
export type EzsigntemplatepackageGetListV1ResponseMPayload = CommonGetListV1ResponseMPayload & EzsigntemplatepackageGetListV1ResponseMPayloadAllOf;


/**
 * @export 
 * A EzsigntemplatepackageGetListV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplatepackageGetListV1ResponseMPayload
 */
export class DefaultObjectEzsigntemplatepackageGetListV1ResponseMPayload extends DefaultObject {
   a_objEzsigntemplatepackage:Array<EzsigntemplatepackageListElement> = []
   iRowReturned:number = 0
   iRowFiltered:number = 0
}


