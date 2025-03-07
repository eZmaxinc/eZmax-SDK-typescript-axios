/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * An EzmaxinvoicingEzsigndocument object containing information about the Ezmaxinvoicing for an Ezsigndocument
 * @export
 * @interface CustomEzmaxinvoicingEzsigndocumentResponse
 */
export interface CustomEzmaxinvoicingEzsigndocumentResponse {
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof CustomEzmaxinvoicingEzsigndocumentResponse
     */
    /*'fkiEzsignfolderID': number;*/
    'fkiEzsignfolderID': number;
    /**
     * The unique ID of the Billingentityinternal.
     * @type {number}
     * @memberof CustomEzmaxinvoicingEzsigndocumentResponse
     */
    /*'fkiBillingentityinternalID'?: number;*/
    'fkiBillingentityinternalID'?: number;
    /**
     * 
     * @type {string}
     * @memberof CustomEzmaxinvoicingEzsigndocumentResponse
     */
    /*'sName': string;*/
    'sName': string;
    /**
     * The description of the Ezsignfolder
     * @type {string}
     * @memberof CustomEzmaxinvoicingEzsigndocumentResponse
     */
    /*'sEzsignfolderDescription': string;*/
    'sEzsignfolderDescription': string;
    /**
     * The name of the document that will be presented to Ezsignfoldersignerassociations
     * @type {string}
     * @memberof CustomEzmaxinvoicingEzsigndocumentResponse
     */
    /*'sEzsigndocumentName': string;*/
    'sEzsigndocumentName': string;
    /**
     * Whether you have access to the Ezsignfolder or not
     * @type {boolean}
     * @memberof CustomEzmaxinvoicingEzsigndocumentResponse
     */
    /*'bEzsignfolderAllowed': boolean;*/
    'bEzsignfolderAllowed': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomEzmaxinvoicingEzsigndocumentResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomEzmaxinvoicingEzsigndocumentResponse
 */
export class DataObjectCustomEzmaxinvoicingEzsigndocumentResponse {
   fkiEzsignfolderID:number = 0
   fkiBillingentityinternalID?:number = undefined
   sName:string = ''
   sEzsignfolderDescription:string = ''
   sEzsigndocumentName:string = ''
   bEzsignfolderAllowed:boolean = false
}

/**
 * @export 
 * A CustomEzmaxinvoicingEzsigndocumentResponse Validation Object
 * @class ValidationObjectCustomEzmaxinvoicingEzsigndocumentResponse
 */
export class ValidationObjectCustomEzmaxinvoicingEzsigndocumentResponse {
   fkiEzsignfolderID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiBillingentityinternalID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   sName = {
      type: 'string',
      required: true
   }
   sEzsignfolderDescription = {
      type: 'string',
      pattern: /^.{0,75}$/,
      required: true
   }
   sEzsigndocumentName = {
      type: 'string',
      required: true
   }
   bEzsignfolderAllowed = {
      type: 'boolean',
      required: true
   }
} 


