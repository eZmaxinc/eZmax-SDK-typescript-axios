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



import { DefaultObject } from '../base'

/**
 * Payload for PUT /1/object/ezsigndocument/{pkiEzsigndocumentID}/editEzsignsignatures
 * @export
 * @interface EzsigndocumentEditEzsignsignaturesV1ResponseMPayload
 */
export interface EzsigndocumentEditEzsignsignaturesV1ResponseMPayload {
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsigndocumentEditEzsignsignaturesV1ResponseMPayload
     */
    'a_pkiEzsignsignatureID': Array<number>;
}
/**
 * A EzsigndocumentEditEzsignsignaturesV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigndocumentEditEzsignsignaturesV1ResponseMPayload
 */
export class DefaultObjectEzsigndocumentEditEzsignsignaturesV1ResponseMPayload extends DefaultObject {
   a_pkiEzsignsignatureID:Array<number> = []
}


