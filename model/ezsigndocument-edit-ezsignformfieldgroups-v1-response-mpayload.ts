/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * Payload for PUT /1/object/ezsigndocument/{pkiEzsigndocumentID}/editEzsignformfieldgroups
 * @export
 * @interface EzsigndocumentEditEzsignformfieldgroupsV1ResponseMPayload
 */
export interface EzsigndocumentEditEzsignformfieldgroupsV1ResponseMPayload {
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsigndocumentEditEzsignformfieldgroupsV1ResponseMPayload
     */
    'a_pkiEzsignformfieldgroupID': Array<number>;
}
/**
 * A EzsigndocumentEditEzsignformfieldgroupsV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigndocumentEditEzsignformfieldgroupsV1ResponseMPayload
 */
export class DefaultObjectEzsigndocumentEditEzsignformfieldgroupsV1ResponseMPayload extends DefaultObject {
   a_pkiEzsignformfieldgroupID:Array<number> = []
}


