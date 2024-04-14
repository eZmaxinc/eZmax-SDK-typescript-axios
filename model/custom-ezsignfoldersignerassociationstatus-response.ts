/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CustomEzsignsignaturestatusResponse } from './custom-ezsignsignaturestatus-response';

/**
 * A Ezsignfoldersignerassociationstatus Object and children to create a complete structure
 * @export
 * @interface CustomEzsignfoldersignerassociationstatusResponse
 */
export interface CustomEzsignfoldersignerassociationstatusResponse {
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof CustomEzsignfoldersignerassociationstatusResponse
     */
    /*'fkiEzsignfoldersignerassociationID': number;*/
    'fkiEzsignfoldersignerassociationID': number;
    /**
     * The last name of the Ezsignsigner
     * @type {string}
     * @memberof CustomEzsignfoldersignerassociationstatusResponse
     * @deprecated
     */
    /*'sEzsignfoldersignerassociationstatusLastname'?: string;*/
    'sEzsignfoldersignerassociationstatusLastname'?: string;
    /**
     * The first name of the Ezsignsigner
     * @type {string}
     * @memberof CustomEzsignfoldersignerassociationstatusResponse
     * @deprecated
     */
    /*'sEzsignfoldersignerassociationstatusFirstname'?: string;*/
    'sEzsignfoldersignerassociationstatusFirstname'?: string;
    /**
     * The description of the Ezsignsigner
     * @type {string}
     * @memberof CustomEzsignfoldersignerassociationstatusResponse
     */
    /*'sEzsignfoldersignerassociationstatusDescriptionX'?: string;*/
    'sEzsignfoldersignerassociationstatusDescriptionX'?: string;
    /**
     * 
     * @type {Array<CustomEzsignsignaturestatusResponse>}
     * @memberof CustomEzsignfoldersignerassociationstatusResponse
     */
    /*'a_objEzsignsignaturestatus': Array<CustomEzsignsignaturestatusResponse>;*/
    'a_objEzsignsignaturestatus': Array<CustomEzsignsignaturestatusResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomEzsignfoldersignerassociationstatusResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomEzsignfoldersignerassociationstatusResponse
 */
export class DataObjectCustomEzsignfoldersignerassociationstatusResponse {
   fkiEzsignfoldersignerassociationID:number = 0
   sEzsignfoldersignerassociationstatusLastname?:string = undefined
   sEzsignfoldersignerassociationstatusFirstname?:string = undefined
   sEzsignfoldersignerassociationstatusDescriptionX?:string = undefined
   a_objEzsignsignaturestatus:Array<CustomEzsignsignaturestatusResponse> = []
}

/**
 * @export 
 * A CustomEzsignfoldersignerassociationstatusResponse Validation Object
 * @class ValidationObjectCustomEzsignfoldersignerassociationstatusResponse
 */
export class ValidationObjectCustomEzsignfoldersignerassociationstatusResponse {
   fkiEzsignfoldersignerassociationID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sEzsignfoldersignerassociationstatusLastname = {
      type: 'string',
      required: false
   }
   sEzsignfoldersignerassociationstatusFirstname = {
      type: 'string',
      required: false
   }
   sEzsignfoldersignerassociationstatusDescriptionX = {
      type: 'string',
      required: false
   }
   a_objEzsignsignaturestatus = {
      type: 'array',
      required: true
   }
} 


