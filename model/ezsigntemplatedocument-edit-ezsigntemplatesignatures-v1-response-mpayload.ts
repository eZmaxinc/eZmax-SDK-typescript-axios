/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * Payload for PUT /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/editEzsigntemplatesignatures
 * @export
 * @interface EzsigntemplatedocumentEditEzsigntemplatesignaturesV1ResponseMPayload
 */
export interface EzsigntemplatedocumentEditEzsigntemplatesignaturesV1ResponseMPayload {
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsigntemplatedocumentEditEzsigntemplatesignaturesV1ResponseMPayload
     */
    'a_pkiEzsigntemplatesignatureID': Array<number>;
}
/**
 * A EzsigntemplatedocumentEditEzsigntemplatesignaturesV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatedocumentEditEzsigntemplatesignaturesV1ResponseMPayload
 */
export class DefaultObjectEzsigntemplatedocumentEditEzsigntemplatesignaturesV1ResponseMPayload extends DefaultObject {
   a_pkiEzsigntemplatesignatureID:Array<number> = []
}


