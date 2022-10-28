/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

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
    'pkiEzsigndocumentID'?: number;
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof EzsigndocumentRequest
     */
    'fkiEzsignfolderID': number;
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigndocumentRequest
     */
    'fkiEzsigntemplateID'?: number;
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof EzsigndocumentRequest
     */
    'fkiEzsignfoldersignerassociationID'?: number;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsigndocumentRequest
     */
    'fkiLanguageID': number;
    /**
     * Indicates where to look for the document binary content.
     * @type {string}
     * @memberof EzsigndocumentRequest
     */
    'eEzsigndocumentSource': EzsigndocumentRequestEEzsigndocumentSourceEnum;
    /**
     * Indicates the format of the document.
     * @type {string}
     * @memberof EzsigndocumentRequest
     */
    'eEzsigndocumentFormat'?: EzsigndocumentRequestEEzsigndocumentFormatEnum;
    /**
     * The Base64 encoded binary content of the document.  This field is Required when eEzsigndocumentSource = Base64.
     * @type {string}
     * @memberof EzsigndocumentRequest
     */
    'sEzsigndocumentBase64'?: string;
    /**
     * The url where the document content resides.  This field is Required when eEzsigndocumentSource = Url.
     * @type {string}
     * @memberof EzsigndocumentRequest
     */
    'sEzsigndocumentUrl'?: string;
    /**
     * Try to repair the document or flatten it if it cannot be used for electronic signature. 
     * @type {boolean}
     * @memberof EzsigndocumentRequest
     */
    'bEzsigndocumentForcerepair'?: boolean;
    /**
     * If the source document is password protected, the password to open/modify it.
     * @type {string}
     * @memberof EzsigndocumentRequest
     */
    'sEzsigndocumentPassword'?: string;
    /**
     * If the document contains an existing PDF form this property must be set.  **Keep** leaves the form as-is in the document.  **Convert** removes the form and convert all the existing fields to Ezsignformfieldgroups and assign them to the specified **fkiEzsignfoldersignerassociationID**
     * @type {string}
     * @memberof EzsigndocumentRequest
     */
    'eEzsigndocumentForm'?: EzsigndocumentRequestEEzsigndocumentFormEnum;
    /**
     * The maximum date and time at which the Ezsigndocument can be signed.
     * @type {string}
     * @memberof EzsigndocumentRequest
     */
    'dtEzsigndocumentDuedate': string;
    /**
     * The name of the document that will be presented to Ezsignfoldersignerassociations
     * @type {string}
     * @memberof EzsigndocumentRequest
     */
    'sEzsigndocumentName': string;
}

export const EzsigndocumentRequestEEzsigndocumentSourceEnum = {
    Base64: 'Base64',
    Ezsigntemplate: 'Ezsigntemplate',
    Url: 'Url'
} as const;
export type EzsigndocumentRequestEEzsigndocumentSourceEnum = typeof EzsigndocumentRequestEEzsigndocumentSourceEnum[keyof typeof EzsigndocumentRequestEEzsigndocumentSourceEnum];

export const EzsigndocumentRequestEEzsigndocumentFormatEnum = {
    Pdf: 'Pdf'
} as const;
export type EzsigndocumentRequestEEzsigndocumentFormatEnum = typeof EzsigndocumentRequestEEzsigndocumentFormatEnum[keyof typeof EzsigndocumentRequestEEzsigndocumentFormatEnum];

export const EzsigndocumentRequestEEzsigndocumentFormEnum = {
    Keep: 'Keep',
    Convert: 'Convert'
} as const;
export type EzsigndocumentRequestEEzsigndocumentFormEnum = typeof EzsigndocumentRequestEEzsigndocumentFormEnum[keyof typeof EzsigndocumentRequestEEzsigndocumentFormEnum];


/**
 * A EzsigndocumentRequest Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigndocumentRequest
 */
export class DefaultObjectEzsigndocumentRequest extends DefaultObject {
   pkiEzsigndocumentID?:number = undefined
   fkiEzsignfolderID:number = 0
   fkiEzsigntemplateID?:number = undefined
   fkiEzsignfoldersignerassociationID?:number = undefined
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
}


