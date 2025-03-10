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
 * The Type for the Attachmentlog
 * @export
 * @enum {string}
 */

export const FieldEAttachmentlogType = {
    AutoValidation: 'AutoValidation',
    CopyFrom: 'CopyFrom',
    CopyTo: 'CopyTo',
    CopyToEzsign: 'CopyToEzsign',
    CreateByEzsign: 'CreateByEzsign',
    Download: 'Download',
    Deleted: 'Deleted',
    Destroyed: 'Destroyed',
    Email: 'Email',
    EmailCC: 'EmailCC',
    EmailCCI: 'EmailCCI',
    Fax: 'Fax',
    ImportedFromExternalSystem: 'ImportedFromExternalSystem',
    ImportedFromEZA: 'ImportedFromEZA',
    ImportedFromFaltour: 'ImportedFromFaltour',
    ImportedFromLonewolf: 'ImportedFromLonewolf',
    ImportedFromProspects: 'ImportedFromProspects',
    Move: 'Move',
    OpenFromEmail: 'OpenFromEmail',
    Purged: 'Purged',
    Reject: 'Reject',
    Rename: 'Rename',
    Restore: 'Restore',
    Scanned: 'Scanned',
    SendToGED: 'SendToGED',
    UnvalidatedBy: 'UnvalidatedBy',
    Upload: 'Upload',
    ValidatedBy: 'ValidatedBy',
    VetinfoUpload: 'VetinfoUpload'
} as const;

export type FieldEAttachmentlogType = typeof FieldEAttachmentlogType[keyof typeof FieldEAttachmentlogType];



