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



import { DefaultObject } from '../base'

/**
 * Payload for POST /1/object/ezsignfoldersignerassociation
 * @export
 * @interface EzsignfoldersignerassociationCreateObjectV1ResponseMPayload
 */
export interface EzsignfoldersignerassociationCreateObjectV1ResponseMPayload {
    /**
     * An array of unique IDs representing the object that were requested to be created.  They are returned in the same order as the array containing the objects to be created that was sent in the request.
     * @type {Array<number>}
     * @memberof EzsignfoldersignerassociationCreateObjectV1ResponseMPayload
     */
    'a_pkiEzsignfoldersignerassociationID': Array<number>;
}
/**
 * A EzsignfoldersignerassociationCreateObjectV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfoldersignerassociationCreateObjectV1ResponseMPayload
 */
export class DefaultObjectEzsignfoldersignerassociationCreateObjectV1ResponseMPayload extends DefaultObject {
   a_pkiEzsignfoldersignerassociationID:Array<number> = []
}


