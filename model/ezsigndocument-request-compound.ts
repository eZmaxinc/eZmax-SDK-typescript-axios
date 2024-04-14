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
import { EzsigndocumentRequest } from './ezsigndocument-request';

/**
 * @type EzsigndocumentRequestCompound
 * An Ezsigndocument Object and children to create a complete structure
 * @export
 */
/*export type EzsigndocumentRequestCompound = EzsigndocumentRequest;*/
export interface EzsigndocumentRequestCompound {
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof EzsigndocumentRequestCompound
     */
    pkiEzsigndocumentID?:number 
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof EzsigndocumentRequestCompound
     */
    fkiEzsignfolderID:number 
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigndocumentRequestCompound
     */
    fkiEzsigntemplateID?:number 
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof EzsigndocumentRequestCompound
     */
    fkiEzsignfoldersignerassociationID?:number 
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsigndocumentRequestCompound
     */
    fkiLanguageID:number 
    /**
     * Indicates where to look for the document binary content.
     * @type {string}
     * @memberof EzsigndocumentRequestCompound
     */
    eEzsigndocumentSource:EzsigndocumentRequestCompoundEEzsigndocumentSourceEnum 
    /**
     * Indicates the format of the document.
     * @type {string}
     * @memberof EzsigndocumentRequestCompound
     */
    eEzsigndocumentFormat?:EzsigndocumentRequestCompoundEEzsigndocumentFormatEnum 
    /**
     * The Base64 encoded binary content of the document.  This field is Required when eEzsigndocumentSource = Base64.
     * @type {string}
     * @memberof EzsigndocumentRequestCompound
     */
    sEzsigndocumentBase64?:string 
    /**
     * The url where the document content resides.  This field is Required when eEzsigndocumentSource = Url.
     * @type {string}
     * @memberof EzsigndocumentRequestCompound
     */
    sEzsigndocumentUrl?:string 
    /**
     * Try to repair the document or flatten it if it cannot be used for electronic signature. 
     * @type {boolean}
     * @memberof EzsigndocumentRequestCompound
     */
    bEzsigndocumentForcerepair?:boolean 
    /**
     * If the source document is password protected, the password to open/modify it.
     * @type {string}
     * @memberof EzsigndocumentRequestCompound
     */
    sEzsigndocumentPassword?:string 
    /**
     * If the document contains an existing PDF form this property must be set.  **Keep** leaves the form as-is in the document.  **Convert** removes the form and convert all the existing fields to Ezsignformfieldgroups and assign them to the specified **fkiEzsignfoldersignerassociationID**  **Discard** removes the form from the document.
     * @type {string}
     * @memberof EzsigndocumentRequestCompound
     */
    eEzsigndocumentForm?:EzsigndocumentRequestCompoundEEzsigndocumentFormEnum 
    /**
     * The maximum date and time at which the Ezsigndocument can be signed.
     * @type {string}
     * @memberof EzsigndocumentRequestCompound
     */
    dtEzsigndocumentDuedate:string 
    /**
     * The name of the document that will be presented to Ezsignfoldersignerassociations
     * @type {string}
     * @memberof EzsigndocumentRequestCompound
     */
    sEzsigndocumentName:string 
    /**
     * This field can be used to store an External ID from the client\'s system.  Anything can be stored in this field, it will never be evaluated by the eZmax system and will be returned AS-IS.  To store multiple values, consider using a JSON formatted structure, a URL encoded string, a CSV or any other custom format. 
     * @type {string}
     * @memberof EzsigndocumentRequestCompound
     */
    sEzsigndocumentExternalid?:string 
}


export const EzsigndocumentRequestCompoundEEzsigndocumentSourceEnum = {
    Base64: 'Base64',
    Ezsigntemplate: 'Ezsigntemplate',
    Url: 'Url'
} as const;
export type EzsigndocumentRequestCompoundEEzsigndocumentSourceEnum = typeof EzsigndocumentRequestCompoundEEzsigndocumentSourceEnum[keyof typeof EzsigndocumentRequestCompoundEEzsigndocumentSourceEnum];

export const EzsigndocumentRequestCompoundEEzsigndocumentFormatEnum = {
    Pdf: 'Pdf',
    Doc: 'Doc',
    Docx: 'Docx',
    Xls: 'Xls',
    Xlsx: 'Xlsx',
    Ppt: 'Ppt',
    Pptx: 'Pptx'
} as const;
export type EzsigndocumentRequestCompoundEEzsigndocumentFormatEnum = typeof EzsigndocumentRequestCompoundEEzsigndocumentFormatEnum[keyof typeof EzsigndocumentRequestCompoundEEzsigndocumentFormatEnum];

export const EzsigndocumentRequestCompoundEEzsigndocumentFormEnum = {
    Keep: 'Keep',
    Convert: 'Convert',
    Discard: 'Discard'
} as const;
export type EzsigndocumentRequestCompoundEEzsigndocumentFormEnum = typeof EzsigndocumentRequestCompoundEEzsigndocumentFormEnum[keyof typeof EzsigndocumentRequestCompoundEEzsigndocumentFormEnum];


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigndocumentRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentRequestCompound
 */
export class DataObjectEzsigndocumentRequestCompound {
    pkiEzsigndocumentID?:number = undefined
    fkiEzsignfolderID:number = 0
    fkiEzsigntemplateID?:number = undefined
    fkiEzsignfoldersignerassociationID?:number = undefined
    fkiLanguageID:number = 0
    eEzsigndocumentSource:EzsigndocumentRequestCompoundEEzsigndocumentSourceEnum = 'Base64'
    eEzsigndocumentFormat?:EzsigndocumentRequestCompoundEEzsigndocumentFormatEnum = undefined
    sEzsigndocumentBase64?:string = undefined
    sEzsigndocumentUrl?:string = undefined
    bEzsigndocumentForcerepair?:boolean = undefined
    sEzsigndocumentPassword?:string = undefined
    eEzsigndocumentForm?:EzsigndocumentRequestCompoundEEzsigndocumentFormEnum = undefined
    dtEzsigndocumentDuedate:string = ''
    sEzsigndocumentName:string = ''
    sEzsigndocumentExternalid?:string = undefined
}

/**
 * @export 
 * A EzsigndocumentRequestCompound Validation Object
 * @class ValidationObjectEzsigndocumentRequestCompound
 */
export class ValidationObjectEzsigndocumentRequestCompound {
   pkiEzsigndocumentID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsignfolderID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigntemplateID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsignfoldersignerassociationID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiLanguageID = {
      type: 'integer',
      minimum: 1,
      maximum: 2,
      required: true
   }
   eEzsigndocumentSource = {
      type: 'string',
      required: true
   }
   eEzsigndocumentFormat = {
      type: 'string',
      required: false
   }
   sEzsigndocumentBase64 = {
      type: 'string',
      required: false
   }
   sEzsigndocumentUrl = {
      type: 'string',
      required: false
   }
   bEzsigndocumentForcerepair = {
      type: 'boolean',
      required: false
   }
   sEzsigndocumentPassword = {
      type: 'string',
      required: false
   }
   eEzsigndocumentForm = {
      type: 'string',
      required: false
   }
   dtEzsigndocumentDuedate = {
      type: 'string',
      required: true
   }
   sEzsigndocumentName = {
      type: 'string',
      required: true
   }
   sEzsigndocumentExternalid = {
      type: 'string',
      pattern: '/^.{0,128}$/',
      required: false
   }
} 


