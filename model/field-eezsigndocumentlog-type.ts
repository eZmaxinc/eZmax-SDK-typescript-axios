/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.7
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * The Ezsigndocumentlog Type.
 * @export
 * @enum {string}
 */

export const FieldEEzsigndocumentlogType = {
    Clone: 'Clone',
    Login: 'Login',
    Sendcode: 'Sendcode',
    Badcode: 'Badcode',
    Goodcode: 'Goodcode',
    Authentication: 'Authentication',
    Createpage: 'Createpage',
    Download: 'Download',
    Send: 'Send',
    Sign: 'Sign',
    Upload: 'Upload',
    View: 'View',
    Completion: 'Completion',
    Changelimitdate: 'Changelimitdate',
    Unsign: 'Unsign',
    ImportFromInstanet: 'ImportFromInstanet',
    SendEmail: 'SendEmail',
    FormCompletion: 'FormCompletion',
    SignatureAttachmentAdd: 'SignatureAttachmentAdd',
    SignatureAttachmentValidation: 'SignatureAttachmentValidation',
    SignatureAttachmentRefused: 'SignatureAttachmentRefused',
    SignatureAttachmentDeleted: 'SignatureAttachmentDeleted',
    DeclinedToSign: 'DeclinedToSign'
} as const;

export type FieldEEzsigndocumentlogType = typeof FieldEEzsigndocumentlogType[keyof typeof FieldEEzsigndocumentlogType];



