/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



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
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfoldersignerassociationCreateObjectV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldersignerassociationCreateObjectV1ResponseMPayload
 */
export class DataObjectEzsignfoldersignerassociationCreateObjectV1ResponseMPayload {
   a_pkiEzsignfoldersignerassociationID:Array<number> = []
}

/**
 * @export 
 * A EzsignfoldersignerassociationCreateObjectV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsignfoldersignerassociationCreateObjectV1ResponseMPayload
 */
export class ValidationObjectEzsignfoldersignerassociationCreateObjectV1ResponseMPayload {
   a_pkiEzsignfoldersignerassociationID = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


