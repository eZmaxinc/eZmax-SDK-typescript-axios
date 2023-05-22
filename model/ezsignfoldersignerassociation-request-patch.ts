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



/**
 * An Ezsignfoldersignerassociation Object
 * @export
 * @interface EzsignfoldersignerassociationRequestPatch
 */
export interface EzsignfoldersignerassociationRequestPatch {
    /**
     * A custom text message that will be added to the email sent.
     * @type {string}
     * @memberof EzsignfoldersignerassociationRequestPatch
     */
    'tEzsignfoldersignerassociationMessage'?: string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfoldersignerassociationRequestPatch Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldersignerassociationRequestPatch
 */
export class DataObjectEzsignfoldersignerassociationRequestPatch {
   tEzsignfoldersignerassociationMessage?:string = undefined
}

/**
 * @export 
 * A EzsignfoldersignerassociationRequestPatch Validation Object
 * @class ValidationObjectEzsignfoldersignerassociationRequestPatch
 */
export class ValidationObjectEzsignfoldersignerassociationRequestPatch {
   tEzsignfoldersignerassociationMessage = {
      type: 'string',
      required: false
   }
} 


