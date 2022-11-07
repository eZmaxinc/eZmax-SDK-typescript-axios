/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * Payload for PUT /1/object/ezsigntemplatepackage/{pkiEzsigntemplatepackageID}/editEzsigntemplatepackagesigners
 * @export
 * @interface EzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseMPayload
 */
export interface EzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseMPayload {
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseMPayload
     */
    'a_pkiEzsigntemplatepackagesignerID': Array<number>;
}
/**
 * A EzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseMPayload
 */
export class DefaultObjectEzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseMPayload extends DefaultObject {
   a_pkiEzsigntemplatepackagesignerID:Array<number> = []
}


