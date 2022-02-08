/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.4
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
    'pkiEzsigndocumentID'?: number;
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
    'eEzsigndocumentFormat': EzsigndocumentRequestEEzsigndocumentFormatEnum;
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
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof EzsigndocumentRequest
     */
    'fkiEzsignfolderID': number;
    /**
     * The maximum date and time at which the Ezsigndocument can be signed.
     * @type {string}
     * @memberof EzsigndocumentRequest
     */
    'dtEzsigndocumentDuedate': string;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsigndocumentRequest
     */
    'fkiLanguageID': number;
    /**
     * The name of the document that will be presented to Ezsignfoldersignerassociations
     * @type {string}
     * @memberof EzsigndocumentRequest
     */
    'sEzsigndocumentName': string;
}

export const EzsigndocumentRequestEEzsigndocumentSourceEnum = {
    Base64: 'Base64',
    Url: 'Url'
} as const;

export type EzsigndocumentRequestEEzsigndocumentSourceEnum = typeof EzsigndocumentRequestEEzsigndocumentSourceEnum[keyof typeof EzsigndocumentRequestEEzsigndocumentSourceEnum];
export const EzsigndocumentRequestEEzsigndocumentFormatEnum = {
    Pdf: 'Pdf'
} as const;

export type EzsigndocumentRequestEEzsigndocumentFormatEnum = typeof EzsigndocumentRequestEEzsigndocumentFormatEnum[keyof typeof EzsigndocumentRequestEEzsigndocumentFormatEnum];


