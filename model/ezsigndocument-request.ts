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
 * An Ezsigndocument Object
 * @export
 * @interface EzsigndocumentRequest
 */
export interface EzsigndocumentRequest {
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof EzsigndocumentRequest
     */
    /*'pkiEzsigndocumentID'?: number;*/
    'pkiEzsigndocumentID'?: number;
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof EzsigndocumentRequest
     */
    /*'fkiEzsignfolderID': number;*/
    'fkiEzsignfolderID': number;
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigndocumentRequest
     */
    /*'fkiEzsigntemplateID'?: number;*/
    'fkiEzsigntemplateID'?: number;
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof EzsigndocumentRequest
     */
    /*'fkiEzsignfoldersignerassociationID'?: number;*/
    'fkiEzsignfoldersignerassociationID'?: number;
    /**
     * The unique ID of the Ezsignimportdocument
     * @type {number}
     * @memberof EzsigndocumentRequest
     */
    /*'fkiEzsignimportdocumentID'?: number;*/
    'fkiEzsignimportdocumentID'?: number;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsigndocumentRequest
     */
    /*'fkiLanguageID': number;*/
    'fkiLanguageID': number;
    /**
     * Indicates where to look for the document binary content.
     * @type {string}
     * @memberof EzsigndocumentRequest
     */
    /*'eEzsigndocumentSource': EzsigndocumentRequestEEzsigndocumentSourceEnum;*/
    'eEzsigndocumentSource': EzsigndocumentRequestEEzsigndocumentSourceEnum;
    /**
     * Indicates the format of the document.
     * @type {string}
     * @memberof EzsigndocumentRequest
     */
    /*'eEzsigndocumentFormat'?: EzsigndocumentRequestEEzsigndocumentFormatEnum;*/
    'eEzsigndocumentFormat'?: EzsigndocumentRequestEEzsigndocumentFormatEnum;
    /**
     * The Base64 encoded binary content of the document.  This field is Required when eEzsigndocumentSource = Base64.
     * @type {string}
     * @memberof EzsigndocumentRequest
     */
    /*'sEzsigndocumentBase64'?: string;*/
    'sEzsigndocumentBase64'?: string;
    /**
     * The url where the document content resides.  This field is Required when eEzsigndocumentSource = Url.
     * @type {string}
     * @memberof EzsigndocumentRequest
     */
    /*'sEzsigndocumentUrl'?: string;*/
    'sEzsigndocumentUrl'?: string;
    /**
     * Try to repair the document or flatten it if it cannot be used for electronic signature. 
     * @type {boolean}
     * @memberof EzsigndocumentRequest
     */
    /*'bEzsigndocumentForcerepair'?: boolean;*/
    'bEzsigndocumentForcerepair'?: boolean;
    /**
     * If the source document is password protected, the password to open/modify it.
     * @type {string}
     * @memberof EzsigndocumentRequest
     */
    /*'sEzsigndocumentPassword'?: string;*/
    'sEzsigndocumentPassword'?: string;
    /**
     * If the document contains an existing PDF form this property must be set.  **Keep** leaves the form as-is in the document.  **Convert** removes the form and convert all the existing fields to Ezsignformfieldgroups and assign them to the specified **fkiEzsignfoldersignerassociationID**  **Discard** removes the form from the document.  **Flatten** prints the form values in the document.
     * @type {string}
     * @memberof EzsigndocumentRequest
     */
    /*'eEzsigndocumentForm'?: EzsigndocumentRequestEEzsigndocumentFormEnum;*/
    'eEzsigndocumentForm'?: EzsigndocumentRequestEEzsigndocumentFormEnum;
    /**
     * The maximum date and time at which the Ezsigndocument can be signed.
     * @type {string}
     * @memberof EzsigndocumentRequest
     */
    /*'dtEzsigndocumentDuedate': string;*/
    'dtEzsigndocumentDuedate': string;
    /**
     * The name of the document that will be presented to Ezsignfoldersignerassociations
     * @type {string}
     * @memberof EzsigndocumentRequest
     */
    /*'sEzsigndocumentName': string;*/
    'sEzsigndocumentName': string;
    /**
     * This field can be used to store an External ID from the client\'s system.  Anything can be stored in this field, it will never be evaluated by the eZmax system and will be returned AS-IS.  To store multiple values, consider using a JSON formatted structure, a URL encoded string, a CSV or any other custom format. 
     * @type {string}
     * @memberof EzsigndocumentRequest
     */
    /*'sEzsigndocumentExternalid'?: string;*/
    'sEzsigndocumentExternalid'?: string;
}

export const EzsigndocumentRequestEEzsigndocumentSourceEnum = {
    Base64: 'Base64',
    Ezsignimportdocument: 'Ezsignimportdocument',
    Ezsigntemplate: 'Ezsigntemplate',
    Url: 'Url'
} as const;
export type EzsigndocumentRequestEEzsigndocumentSourceEnum = typeof EzsigndocumentRequestEEzsigndocumentSourceEnum[keyof typeof EzsigndocumentRequestEEzsigndocumentSourceEnum];

export const EzsigndocumentRequestEEzsigndocumentFormatEnum = {
    Pdf: 'Pdf',
    Doc: 'Doc',
    Docx: 'Docx',
    Xls: 'Xls',
    Xlsx: 'Xlsx',
    Ppt: 'Ppt',
    Pptx: 'Pptx'
} as const;
export type EzsigndocumentRequestEEzsigndocumentFormatEnum = typeof EzsigndocumentRequestEEzsigndocumentFormatEnum[keyof typeof EzsigndocumentRequestEEzsigndocumentFormatEnum];

export const EzsigndocumentRequestEEzsigndocumentFormEnum = {
    Keep: 'Keep',
    Convert: 'Convert',
    Discard: 'Discard',
    Flatten: 'Flatten'
} as const;
export type EzsigndocumentRequestEEzsigndocumentFormEnum = typeof EzsigndocumentRequestEEzsigndocumentFormEnum[keyof typeof EzsigndocumentRequestEEzsigndocumentFormEnum];


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigndocumentRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentRequest
 */
export class DataObjectEzsigndocumentRequest {
   pkiEzsigndocumentID?:number = undefined
   fkiEzsignfolderID:number = 0
   fkiEzsigntemplateID?:number = undefined
   fkiEzsignfoldersignerassociationID?:number = undefined
   fkiEzsignimportdocumentID?:number = undefined
   fkiLanguageID:number = 0
   eEzsigndocumentSource:EzsigndocumentRequestEEzsigndocumentSourceEnum = 'Base64'
   eEzsigndocumentFormat?:EzsigndocumentRequestEEzsigndocumentFormatEnum = undefined
   sEzsigndocumentBase64?:string = undefined
   sEzsigndocumentUrl?:string = undefined
   bEzsigndocumentForcerepair?:boolean = undefined
   sEzsigndocumentPassword?:string = undefined
   eEzsigndocumentForm?:EzsigndocumentRequestEEzsigndocumentFormEnum = undefined
   dtEzsigndocumentDuedate:string = ''
   sEzsigndocumentName:string = ''
   sEzsigndocumentExternalid?:string = undefined
}

/**
 * @export 
 * A EzsigndocumentRequest Validation Object
 * @class ValidationObjectEzsigndocumentRequest
 */
export class ValidationObjectEzsigndocumentRequest {
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
   fkiEzsignimportdocumentID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
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
      pattern: /^.{0,128}$/,
      required: false
   }
} 


