/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.8
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A Ezsigntemplatedocument Object
 * @export
 * @interface EzsigntemplatedocumentRequest
 */
export interface EzsigntemplatedocumentRequest {
    /**
     * The unique ID of the Ezsigntemplatedocument
     * @type {number}
     * @memberof EzsigntemplatedocumentRequest
     */
    'pkiEzsigntemplatedocumentID'?: number;
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigntemplatedocumentRequest
     */
    'fkiEzsigntemplateID': number;
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof EzsigntemplatedocumentRequest
     */
    'fkiEzsigndocumentID'?: number;
    /**
     * The unique ID of the Ezsigntemplatesigner
     * @type {number}
     * @memberof EzsigntemplatedocumentRequest
     */
    'fkiEzsigntemplatesignerID'?: number;
    /**
     * The name of the Ezsigntemplatedocument.
     * @type {string}
     * @memberof EzsigntemplatedocumentRequest
     */
    'sEzsigntemplatedocumentName': string;
    /**
     * Indicates where to look for the document binary content.
     * @type {string}
     * @memberof EzsigntemplatedocumentRequest
     */
    'eEzsigntemplatedocumentSource': EzsigntemplatedocumentRequestEEzsigntemplatedocumentSourceEnum;
    /**
     * Indicates the format of the template.
     * @type {string}
     * @memberof EzsigntemplatedocumentRequest
     */
    'eEzsigntemplatedocumentFormat'?: EzsigntemplatedocumentRequestEEzsigntemplatedocumentFormatEnum;
    /**
     * The Base64 encoded binary content of the document.  This field is Required when eEzsigntemplatedocumentSource = Base64.
     * @type {string}
     * @memberof EzsigntemplatedocumentRequest
     */
    'sEzsigntemplatedocumentBase64'?: string;
    /**
     * The url where the document content resides.  This field is Required when eEzsigntemplatedocumentSource = Url.
     * @type {string}
     * @memberof EzsigntemplatedocumentRequest
     */
    'sEzsigntemplatedocumentUrl'?: string;
    /**
     * Try to repair the document or flatten it if it cannot be used for electronic signature.
     * @type {boolean}
     * @memberof EzsigntemplatedocumentRequest
     */
    'bEzsigntemplatedocumentForcerepair'?: boolean;
    /**
     * If the document contains an existing PDF form this property must be set.  **Keep** leaves the form as-is in the document.  **Convert** removes the form and convert all the existing fields to Ezsigntemplateformfieldgroups and assign them to the specified **fkiEzsigntemplatesignerID**
     * @type {string}
     * @memberof EzsigntemplatedocumentRequest
     */
    'eEzsigntemplatedocumentForm'?: EzsigntemplatedocumentRequestEEzsigntemplatedocumentFormEnum;
    /**
     * If the source template is password protected, the password to open/modify it.
     * @type {string}
     * @memberof EzsigntemplatedocumentRequest
     */
    'sEzsigntemplatedocumentPassword'?: string;
}

export const EzsigntemplatedocumentRequestEEzsigntemplatedocumentSourceEnum = {
    Base64: 'Base64',
    Url: 'Url',
    Ezsigndocument: 'Ezsigndocument'
} as const;

export type EzsigntemplatedocumentRequestEEzsigntemplatedocumentSourceEnum = typeof EzsigntemplatedocumentRequestEEzsigntemplatedocumentSourceEnum[keyof typeof EzsigntemplatedocumentRequestEEzsigntemplatedocumentSourceEnum];
export const EzsigntemplatedocumentRequestEEzsigntemplatedocumentFormatEnum = {
    Pdf: 'Pdf'
} as const;

export type EzsigntemplatedocumentRequestEEzsigntemplatedocumentFormatEnum = typeof EzsigntemplatedocumentRequestEEzsigntemplatedocumentFormatEnum[keyof typeof EzsigntemplatedocumentRequestEEzsigntemplatedocumentFormatEnum];
export const EzsigntemplatedocumentRequestEEzsigntemplatedocumentFormEnum = {
    Keep: 'Keep',
    Convert: 'Convert'
} as const;

export type EzsigntemplatedocumentRequestEEzsigntemplatedocumentFormEnum = typeof EzsigntemplatedocumentRequestEEzsigntemplatedocumentFormEnum[keyof typeof EzsigntemplatedocumentRequestEEzsigntemplatedocumentFormEnum];

